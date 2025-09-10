#start with cmd:

#py -3 "summarize_o365_audit.py" "xxxx_log_input_suspect_full.csv" -o "audit_summary.txt"



#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
summarize_o365_audit.py
- Liest ein vorgefiltertes Office 365 Audit Log (CSV).
- Aggregiert pro Tag (ältester -> neuester).
- Zählt die tatsächlich betroffenen Elemente (nicht die Anzahl Events).
- Gibt Datum + Zeilen "Anzahl Beschreibung  ( Operation)" aus.
- Schreibt Ausgabe auf Konsole und in Datei (UTF-8 mit BOM).

Getestet mit Python 3.9+ (nur Standardbibliothek).
"""

import argparse
import csv
import json
import os
import re
from collections import defaultdict, Counter
from datetime import datetime

# -------------------- Konfiguration --------------------

KNOWN_OPS = [
    "UserLoginFailed", "UserLoggedIn", "Update", "SharingSet",
    "SharingInheritanceBroken", "Send", "SecureLinkUpdated", "SecureLinkCreated",
    "PageViewed", "New-InboxRule", "MoveToDeletedItems", "MailItemsAccessed",
    "FileAccessedExtended", "FileAccessed", "Create", "AddedToSecureLink",
]

DESCRIPTIONS = {
    "UserLoginFailed": "fehlgeschlagene Anmeldungen",
    "UserLoggedIn": "erfolgreiche Anmeldungen",
    "Update": "Aktualisierungen",
    "SharingSet": "Freigaben gesetzt",
    "SharingInheritanceBroken": "Vererbte Freigabe aufgehoben",
    "Send": "gesendete E-Mails",
    "SecureLinkUpdated": "Sicherer Link aktualisiert",
    "SecureLinkCreated": "Sicherer Link erstellt",
    "PageViewed": "Seitenaufrufe",
    "New-InboxRule": "neue Posteingangsregeln",
    "MoveToDeletedItems": 'Elemente in "Gelöscht" verschoben',
    "MailItemsAccessed": "lesender Zugriff auf MailItems",
    "FileAccessedExtended": "Dateizugriffe (Extended)",
    "FileAccessed": "Dateizugriffe",
    "Create": "Erstellt",
    "AddedToSecureLink": "E-Mail-Adressen Zugriff auf geteiltes Objekt geben",
}

# bevorzugte Reihenfolge der Operationen innerhalb eines Tages
PREFERRED_ORDER = [
    "MailItemsAccessed",
    "AddedToSecureLink",
    "FileAccessed",
    "FileAccessedExtended",
    "SharingSet",
]

DATE_COLUMNS = [
    "CreationTime", "CreationDate", "CreationDateUTC", "TimeGenerated", "EventCreationTime"
]

# Mögliche Datumsformate – beliebig erweiterbar
DATE_FORMATS = [
    "%d.%m.%Y %H:%M:%S",
    "%d.%m.%Y %H:%M",
    "%d.%m.%Y",  # Fallback ohne Uhrzeit
    "%Y-%m-%dT%H:%M:%S.%fZ",
    "%Y-%m-%dT%H:%M:%SZ",
    "%Y-%m-%d %H:%M:%S",
    "%m/%d/%Y %I:%M:%S %p",
    "%m/%d/%Y %H:%M",
]

# -------------------- Utilities --------------------

NBSP_CHARS = "\u00A0\u2007\u202F\u200B\u200C\u200D"

def normalize_op_text(s: str) -> str:
    if not s:
        return ""
    s = s.replace('"', "").replace("\r", " ").replace("\n", " ")
    for ch in NBSP_CHARS:
        s = s.replace(ch, " ")
    s = re.sub(r"\s+", " ", s)
    return s.strip()

def extract_known_ops_from_token(token: str, ops=KNOWN_OPS):
    """
    Zerlegt einen Token (z. B. 'MailItemsAccessedUpdate') in bekannte Operationen.
    Greedy, längste Treffer bevorzugt, keine Regex-Backtracking-Probleme.
    """
    if not token:
        return []
    tlow = token.lower()
    occurrences = []
    for op in sorted(ops, key=len, reverse=True):
        olow = op.lower()
        start = 0
        while True:
            idx = tlow.find(olow, start)
            if idx == -1:
                break
            occurrences.append((idx, op, len(op)))
            start = idx + len(op)
    # Sortiere nach Startindex (aufsteigend), bei Gleichstand längere zuerst
    occurrences.sort(key=lambda x: (x[0], -x[2]))

    result = []
    consumed_until = -1
    for idx, op, length in occurrences:
        if idx >= consumed_until:
            result.append(op)
            consumed_until = idx + length
    return result

def recognize_ops_from_raw(op_raw: str):
    s = normalize_op_text(op_raw)
    if not s:
        return []
    # Zuerst normal splitten
    tokens = [t for t in re.split(r"[\s,;|]+", s) if t]
    found = []
    for t in tokens:
        parts = extract_known_ops_from_token(t)
        found.extend(parts)
    if not found:
        # Fallback: gesamten String scannen
        found = extract_known_ops_from_token(s)
    return found

def parse_audit_json(text: str):
    if not text:
        return None
    t = text.strip()
    # Versuche 1: direkt
    try:
        return json.loads(t)
    except Exception:
        pass
    # Versuche 2: doppelt gequotet -> un-escapen
    try:
        t2 = t.strip('"').replace('""', '"')
        return json.loads(t2)
    except Exception:
        return None

def first_present(dct, names):
    if not isinstance(dct, dict):
        return None
    for n in names:
        if n in dct and dct[n] not in (None, "", []):
            return dct[n]
    return None

def to_int_or_none(v):
    try:
        if isinstance(v, bool):
            return None
        return int(v)
    except Exception:
        return None

def count_from_candidates(audit, candidates):
    if not isinstance(audit, dict):
        return None
    for n in candidates:
        if n in audit:
            v = audit[n]
            if v is None:
                continue
            if isinstance(v, (list, tuple, set)):
                return len(list(v))
            if isinstance(v, dict):
                return len(v)
            if isinstance(v, (int, float)):
                return int(v)
            if isinstance(v, str):
                parts = [p for p in re.split(r"[,; ]+", v) if p.strip()]
                if parts:
                    return len(parts)
    return None

def get_mailitemsaccessed_count(audit):
    if not isinstance(audit, dict):
        return 1
    c = count_from_candidates(audit, [
        "ItemAccesses", "Items", "ItemIds", "AffectedItems",
        "IdList", "AccessedItems", "MailboxItemIds"
    ])
    if c:
        return c
    for n in ["ItemCount", "Count", "TotalItems", "AggregatedEventCount", "AggregatedEventCountAll"]:
        v = first_present(audit, [n])
        iv = to_int_or_none(v)
        if iv:
            return iv
    return 1

def get_object_display(audit):
    if not isinstance(audit, dict):
        return None
    # 1) vollständige URLs
    url = first_present(audit, ["ItemUrl", "ObjectUrl", "FileUrl", "SourceFileUrl"])
    if url:
        return str(url)
    # 2) Objekt-/Pfad-Felder
    oid = first_present(audit, ["ObjectId", "ObjectID", "ObjectIdOrPath", "TargetFilePath",
                                "ListItemUniqueId", "ObjectUniqueId", "ObjectName"])
    if oid:
        return str(oid)
    # 3) SharePoint: Site + Relative
    site = first_present(audit, ["SiteUrl", "WebUrl"])
    rel = first_present(audit, ["SourceRelativeUrl", "ObjectRelativeUrl", "ItemRelativeUrl",
                                "SourceFilePath", "FilePath", "SourceFileFolderPath"])
    if site and rel:
        site = str(site).rstrip("/")
        rel = str(rel).lstrip("/")
        return f"{site}/{rel}"
    # 4) Dateiname als Fallback
    name = first_present(audit, ["SourceFileName", "FileName", "DocumentLocation"])
    if name:
        return str(name)
    return None

def get_added_to_secure_link_info(audit):
    obj = get_object_display(audit)
    count = count_from_candidates(audit, [
        "Users", "TargetUsers", "Recipients", "UsersWithAccess", "UserSharedWith",
        "Targets", "UserIds", "Principals", "GrantedToIdentities"
    ])
    if not count:
        single = first_present(audit, ["TargetUserOrGroupName", "UserSharedWith", "SharedWith"])
        if isinstance(single, str):
            parts = [p for p in re.split(r"[,; ]+", single) if p.strip()]
            if parts:
                count = len(parts)
    if not count:
        count = 1
    return count, obj

def parse_date_to_key(row: dict) -> str:
    raw = None
    for col in DATE_COLUMNS:
        if col in row and row[col]:
            raw = row[col]
            break
    if not raw:
        return "01.01.1970"
    s = str(raw).strip()
    # Ersetze T/Z für fromisoformat-kompatible Strings
    s = s.replace("Z", "+00:00")
    # Häufige Formate durchprobieren
    for fmt in DATE_FORMATS:
        try:
            dt = datetime.strptime(s, fmt)
            return dt.strftime("%d.%m.%Y")
        except Exception:
            continue
    # Fallback: versuche ISO
    try:
        dt = datetime.fromisoformat(s)
        return dt.strftime("%d.%m.%Y")
    except Exception:
        pass
    # Letzter Fallback: rohe dd.mm.yyyy mit Regex
    m = re.search(r"(\d{2})\.(\d{2})\.(\d{4})", s)
    if m:
        return f"{m.group(1)}.{m.group(2)}.{m.group(3)}"
    return "01.01.1970"

# -------------------- Hauptlogik --------------------

def summarize(csv_path: str):
    # summary[date][op] -> {"total": int, "per_object": Counter()}
    summary = defaultdict(lambda: defaultdict(dict))

    with open(csv_path, "r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            date_key = parse_date_to_key(row)
            op_raw = (row.get("Operation") or "").strip()
            if not op_raw:
                continue

            # AudtData JSON parsen (falls vorhanden)
            audit = parse_audit_json(row.get("AuditData"))

            ops = recognize_ops_from_raw(op_raw)
            if not ops:
                # Wenn nichts erkannt wird, lieber überspringen statt „Sammelzeile“
                continue

            for op in ops:
                if op == "MailItemsAccessed":
                    cnt = get_mailitemsaccessed_count(audit)
                    entry = summary[date_key].setdefault(op, {"total": 0})
                    entry["total"] += cnt

                elif op == "AddedToSecureLink":
                    cnt, obj = get_added_to_secure_link_info(audit)
                    entry = summary[date_key].setdefault(op, {"total": 0, "per_object": Counter()})
                    entry["total"] += cnt
                    key = obj if obj else "(kein Objekt verfügbar)"
                    entry["per_object"][key] += cnt

                elif op in {"FileAccessed", "FileAccessedExtended", "SharingSet", "SecureLinkCreated", "SecureLinkUpdated"}:
                    obj = get_object_display(audit)
                    cnt = count_from_candidates(audit, ["ItemCount", "Count", "TotalItems", "AffectedItems", "Items"])
                    if not cnt:
                        cnt = 1
                    entry = summary[date_key].setdefault(op, {"total": 0, "per_object": Counter()})
                    entry["total"] += cnt
                    key = obj if obj else "(kein Objekt verfügbar)"
                    entry["per_object"][key] += cnt

                else:
                    # generische Zählung
                    cnt = None
                    if isinstance(audit, dict):
                        cnt = count_from_candidates(audit, ["Items", "ItemIds", "AffectedItems", "Targets", "Rows", "Accesses"])
                        if not cnt:
                            for n in ["ItemCount", "Count", "TotalItems", "AggregatedEventCount"]:
                                v = first_present(audit, [n])
                                iv = to_int_or_none(v)
                                if iv:
                                    cnt = iv
                                    break
                    if not cnt:
                        cnt = 1
                    entry = summary[date_key].setdefault(op, {"total": 0})
                    entry["total"] += cnt

    return summary

def sort_ops_for_day(op_dict: dict):
    ops = list(op_dict.keys())
    head = [o for o in ops if o in PREFERRED_ORDER]
    tail = sorted([o for o in ops if o not in PREFERRED_ORDER])
    # Head in definierter Reihenfolge
    ordered_head = [o for o in PREFERRED_ORDER if o in head]
    return ordered_head + tail

def build_output(summary: dict) -> str:
    # Tage ältester -> neuester
    def parse_key(k):
        try:
            return datetime.strptime(k, "%d.%m.%Y")
        except Exception:
            return datetime(1970, 1, 1)

    lines = []
    for date_key in sorted(summary.keys(), key=parse_key):
        lines.append(f"{date_key}:")
        ops_order = sort_ops_for_day(summary[date_key])
        for op in ops_order:
            desc = DESCRIPTIONS.get(op, op)
            entry = summary[date_key][op]
            per_object = entry.get("per_object")
            if isinstance(per_object, Counter):
                for obj, cnt in sorted(per_object.items(), key=lambda kv: kv[0]):
                    obj_label = obj if obj else "(kein Objekt verfügbar)"
                    lines.append(f"{cnt} {desc} (Objekt: {obj_label})  ( {op})")
            else:
                total = int(entry.get("total", 0) or 0)
                if total <= 0:
                    total = 1
                lines.append(f"{total} {desc}  ( {op})")
        lines.append("")  # Leerzeile zwischen Tagen
    return "\n".join(lines).rstrip() + "\n"

def main():
    ap = argparse.ArgumentParser(description="O365 Audit CSV zusammenfassen (betroffene Elemente zählen).")
    ap.add_argument("csv", help="Pfad zur CSV-Datei (Audit Log Export)")
    ap.add_argument("-o", "--out", dest="outfile", default=None, help="Zieldatei für die Zusammenfassung (TXT)")
    args = ap.parse_args()

    csv_path = args.csv
    if not os.path.exists(csv_path):
        raise SystemExit(f"CSV nicht gefunden: {csv_path}")

    summary = summarize(csv_path)
    output = build_output(summary)

    # Konsole
    print(output, end="")

    # Datei schreiben (UTF-8 mit BOM)
    out_path = args.outfile or (os.path.splitext(os.path.basename(csv_path))[0] + "_summary.txt")
    out_dir = os.path.dirname(out_path)
    if out_dir and not os.path.exists(out_dir):
        os.makedirs(out_dir, exist_ok=True)
    with open(out_path, "w", encoding="utf-8-sig", newline="\n") as f:
        f.write(output)

    # Hinweis
    full = os.path.abspath(out_path)
    print(f"Zusammenfassung geschrieben nach: {full}")

if __name__ == "__main__":
    main()
