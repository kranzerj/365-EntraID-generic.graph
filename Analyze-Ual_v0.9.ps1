#.\Analyze-Ual.ps1 -InputCsv ".\bernd_log_input.csv"

param(
    [Parameter(Mandatory=$true)]
    [string]$InputCsv,
    [string]$OutSummary,
    [string]$OutFull
)

# ---------- Hilfsfunktionen ----------

function Get-CsvDelimiter {
    param([string]$Path)
    $firstLine = Get-Content -Path $Path -TotalCount 1 -ErrorAction Stop
    $semis  = ($firstLine.ToCharArray() | Where-Object { $_ -eq ';' }).Count
    $commas = ($firstLine.ToCharArray() | Where-Object { $_ -eq ',' }).Count
    if ($semis -gt $commas) { return ';' } else { return ',' }
}

function Try-NormalizeIp {
    param([string]$Raw)
    if ([string]::IsNullOrWhiteSpace($Raw)) { return $null }

    # XFF/Proxy-Kette: "ip1, ip2, ..." -> erste nehmen
    $candidate = $Raw.Split(',')[0].Trim()

    # IPv6 mit Port: [2001:db8::1]:443
    if ($candidate -match '^\[(?<ip>[^\]]+)\](?::\d+)?$') {
        $ip = $matches['ip']
    }
    # IPv4 evtl. mit Port
    elseif ($candidate -match '^\d{1,3}(\.\d{1,3}){3}(:\d+)?$') {
        $ip = ($candidate -replace ':\d+$','')
    }
    else {
        # vermutlich IPv6 ohne Klammern
        $ip = $candidate
    }

    # Validierung
    [System.Net.IPAddress]$parsed = $null
    if ([System.Net.IPAddress]::TryParse($ip, [ref]$parsed)) { return $ip }
    return $null
}

function Get-ParsedAuditData {
    param($Row)
    $json = $Row.AuditData
    if ([string]::IsNullOrWhiteSpace($json)) { return $null }
    try { return ($json | ConvertFrom-Json -ErrorAction Stop) }
    catch { return $null }
}

function Get-CanonicalIp {
    param($Row)
    $data = Get-ParsedAuditData -Row $Row

    $candidates = @()
    if ($data) {
        if ($data.PSObject.Properties.Name -contains 'ClientIPAddress') { $candidates += [string]$data.ClientIPAddress }
        if ($data.PSObject.Properties.Name -contains 'ClientIP')        { $candidates += [string]$data.ClientIP }
        if ($data.PSObject.Properties.Name -contains 'ActorIPAddress')  { $candidates += [string]$data.ActorIPAddress }
    }
    if ($Row.PSObject.Properties.Name -contains 'ClientIP') { $candidates += [string]$Row.ClientIP }

    foreach ($c in $candidates) {
        $norm = Try-NormalizeIp $c
        if ($null -ne $norm) { return $norm }
    }
    return $null
}

function Get-EventDate {
    param($Row)
    $data = Get-ParsedAuditData -Row $Row
    foreach ($name in @('CreationDate','CreationTime','EventCreationTime','TimeGenerated')) {
        if ($Row.PSObject.Properties.Name -contains $name -and $Row.$name) { return $Row.$name }
    }
    if ($data -and $data.PSObject.Properties.Name -contains 'CreationTime' -and $data.CreationTime) {
        return $data.CreationTime
    }
    return $null
}

function Get-Operation {
    param($Row)
    $data = Get-ParsedAuditData -Row $Row
    foreach ($name in @('Operation','Action')) {
        if ($Row.PSObject.Properties.Name -contains $name -and $Row.$name) { return $Row.$name }
    }
    if ($data -and $data.PSObject.Properties.Name -contains 'Operation' -and $data.Operation) {
        return $data.Operation
    }
    return $null
}

# --- NEU: numerische Sortierinformation für IPv4/IPv6 (IPv4 zuerst) ---

function Get-IpSortInfo {
    param([string]$IpString)
    [System.Net.IPAddress]$p = $null
    if (-not [System.Net.IPAddress]::TryParse($IpString, [ref]$p)) { return $null }

    if ($p.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) {
        # IPv4 -> 32-bit Nummer bauen
        $b = $p.GetAddressBytes()  # big-endian
        $key = [UInt64](
            ($b[0] -shl 24) -bor
            ($b[1] -shl 16) -bor
            ($b[2] -shl 8)  -bor
             $b[3]
        )
        return [pscustomobject]@{ Family = 4; Key = $key }
    } else {
        # IPv6 -> BigInteger (little-endian erwartet)
        $bytes = $p.GetAddressBytes()
        [Array]::Reverse($bytes)   # zu little-endian drehen
        $bytes = $bytes + 0        # Vorzeichenbit neutralisieren
        $big = [System.Numerics.BigInteger]::new($bytes)
        return [pscustomobject]@{ Family = 6; Key = $big }
    }
}

# ---------- CSV laden ----------

if (-not (Test-Path -LiteralPath $InputCsv)) {
    throw "Datei nicht gefunden: $InputCsv"
}

$delimiter = Get-CsvDelimiter -Path $InputCsv
Write-Host ("Erkanntes Trennzeichen: '{0}'" -f $delimiter)

$rows = Import-Csv -LiteralPath $InputCsv -Delimiter $delimiter

if (-not $OutSummary) {
    $base = [IO.Path]::GetFileNameWithoutExtension($InputCsv)
    $dir  = [IO.Path]::GetDirectoryName($InputCsv)
    $OutSummary = Join-Path $dir "${base}_suspect_summary.csv"
}
if (-not $OutFull) {
    $base = [IO.Path]::GetFileNameWithoutExtension($InputCsv)
    $dir  = [IO.Path]::GetDirectoryName($InputCsv)
    $OutFull = Join-Path $dir "${base}_suspect_full.csv"
}

# ---------- IPs sammeln (Events ohne IP = legitime Admin/Backend -> ignorieren) ----------

$ipCounts  = @{}
$ipSamples = @{}
foreach ($r in $rows) {
    $ip = Get-CanonicalIp -Row $r
    if ([string]::IsNullOrWhiteSpace($ip)) { continue }

    if (-not $ipCounts.ContainsKey($ip)) {
        $ipCounts[$ip] = 0
        $ipSamples[$ip] = New-Object System.Collections.Generic.List[string]
    }
    $ipCounts[$ip]++
    $op = Get-Operation -Row $r
    if ($op -and $ipSamples[$ip].Count -lt 5 -and -not $ipSamples[$ip].Contains($op)) {
        $ipSamples[$ip].Add($op)
    }
}

if ($ipCounts.Count -eq 0) {
    Write-Host "Keine Events mit Client-IP gefunden. Es gibt nichts zu klassifizieren."
    "Date,IP,Operation" | Out-File -FilePath $OutSummary -Encoding utf8
    "" | Out-File -FilePath $OutFull -Encoding utf8
    return
}

# ------- NEU: Numerische Sortierung (IPv4 -> IPv6) --------
$sortedIps =
    $ipCounts.Keys |
    ForEach-Object {
        $info = Get-IpSortInfo $_
        if ($null -ne $info) {
            [pscustomobject]@{ Ip = $_; Family = $info.Family; Key = $info.Key }
        }
    } |
    Sort-Object -Property Family, Key |
    Select-Object -ExpandProperty Ip

# ---------- Interaktive Klassifizierung ----------

$decisions = @{}  # IP -> $true (erlaubt) / $false (nicht erlaubt)
$idx = 0
while ($idx -lt $sortedIps.Count) {
    $ip = $sortedIps[$idx]
    $count = $ipCounts[$ip]
    $samples = ($ipSamples[$ip] -join ", ")

    Write-Host ""
    Write-Host ("[{0}/{1}] IP: {2}  (Events: {3})" -f ($idx+1), $sortedIps.Count, $ip, $count)
    if ($samples) { Write-Host ("Beispiele (Operationen): {0}" -f $samples) }
    $answer = Read-Host "Berechtigt? (y/j = ja, n = nein, b = zurück)"

    switch -Regex ($answer.ToLower()) {
        '^(y|j)$' { $decisions[$ip] = $true;  $idx++; continue }
        '^n$'     { $decisions[$ip] = $false; $idx++; continue }
        '^b$'     { if ($idx -gt 0) { $idx-- } else { Write-Host "Schon bei der ersten IP." }; continue }
        default   { Write-Host "Bitte 'y', 'j', 'n' oder 'b' eingeben."; continue }
    }
}

# ---------- Ergebnisse erzeugen ----------

$suspectRows = New-Object System.Collections.Generic.List[object]
$summaryRows = New-Object System.Collections.Generic.List[pscustomobject]

foreach ($r in $rows) {
    $ip = Get-CanonicalIp -Row $r
    if ([string]::IsNullOrWhiteSpace($ip)) { continue }               # legitime Admin-/Backend-Events auslassen
    if ($decisions.ContainsKey($ip) -and $decisions[$ip]) { continue } # erlaubte IP -> überspringen

    $suspectRows.Add($r)

    $date = Get-EventDate -Row $r
    $op   = Get-Operation -Row $r
    $summaryRows.Add([pscustomobject]@{
        Date      = $date
        IP        = $ip
        Operation = $op
    })
}

# ---------- Export ----------

if ($summaryRows.Count -eq 0) {
    Write-Host "Keine verdächtigen Einträge gefunden."
    "Date,IP,Operation" | Out-File -FilePath $OutSummary -Encoding utf8
    "" | Out-File -FilePath $OutFull -Encoding utf8
    Write-Host ("Leere Ergebnisdateien erzeugt:`n  {0}`n  {1}" -f $OutSummary, $OutFull)
    return
}

try {
    $summaryRows | Sort-Object { [datetime]$_.Date } | Export-Csv -Path $OutSummary -NoTypeInformation -Encoding utf8
} catch {
    $summaryRows | Export-Csv -Path $OutSummary -NoTypeInformation -Encoding utf8
}
$suspectRows | Export-Csv -Path $OutFull -NoTypeInformation -Encoding utf8

Write-Host ""
Write-Host "Fertig."
Write-Host ("Zusammenfassung: {0}" -f $OutSummary)
Write-Host ("Vollständige Einträge: {0}" -f $OutFull)
