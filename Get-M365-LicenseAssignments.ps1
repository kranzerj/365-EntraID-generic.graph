<#
.SYNOPSIS
Listet pro M365-Lizenz auf, welche Benutzer die Lizenz direkt und welche über Gruppen zugewiesen bekommen.
Optionaler CSV-Export: eine Datei pro Lizenz.

.USAGE
# Einmalig die benötigten Module installieren (statt Microsoft.Graph Meta-Modul):
# Install-Module Microsoft.Graph.Authentication,Microsoft.Graph.Users,Microsoft.Graph.Groups,Microsoft.Graph.Identity.DirectoryManagement -Scope CurrentUser

# Skript ausführen (Konsole):
# .\Get-M365-LicenseAssignments.ps1
# .\Get-M365-LicenseAssignments.ps1 -OutFolder "C:\Temp\LicenseReports"
# .\Get-M365-LicenseAssignments.ps1 -IncludeSkus "M365_E3","ENTERPRISEPREMIUM" -OutFolder "C:\Temp\LicenseReports"

.NOTES
- Empfohlen: PowerShell 7+ (verhindert 4096-Funktionslimit von Windows PowerShell 5.1)
- Benötigte Graph-Scopes: User.Read.All, Group.Read.All, Directory.Read.All
#>

[CmdletBinding()]
param(
  [string]$OutFolder,
  [string[]]$IncludeSkus
)

# ---------- 1) Module laden & verbinden ----------
try {
  Import-Module Microsoft.Graph.Authentication,Microsoft.Graph.Users,Microsoft.Graph.Groups,Microsoft.Graph.Identity.DirectoryManagement -ErrorAction Stop
} catch {
  Write-Error "Benötigte Module fehlen. Bitte ausführen:
Install-Module Microsoft.Graph.Authentication,Microsoft.Graph.Users,Microsoft.Graph.Groups,Microsoft.Graph.Identity.DirectoryManagement -Scope CurrentUser"
  exit 1
}

try {
  Connect-MgGraph -Scopes "User.Read.All","Group.Read.All","Directory.Read.All" | Out-Null
} catch {
  Write-Error "Connect-MgGraph fehlgeschlagen: $($_.Exception.Message)"
  exit 1
}

# ---------- 2) SKUs laden & filtern ----------
try {
  $skus = Get-MgSubscribedSku | Select-Object SkuId,SkuPartNumber
} catch {
  Write-Error "Get-MgSubscribedSku fehlgeschlagen: $($_.Exception.Message)"
  exit 1
}

if ($IncludeSkus) {
  $skus = $skus | Where-Object { $_.SkuPartNumber -and ($IncludeSkus -contains $_.SkuPartNumber) }
}

# Nur gültige SKUs behalten (SkuId und SkuPartNumber vorhanden)
$skus = $skus | Where-Object { $_.SkuId -and $_.SkuPartNumber }

if (-not $skus -or $skus.Count -eq 0) {
  Write-Error "Keine (passenden) SKUs gefunden. Prüfe Abos oder Parameter -IncludeSkus."
  exit 1
}

# Lookup: Key = stringifizierte SkuId
$skuById = @{}
foreach ($s in $skus) {
  $skuById[[string]$s.SkuId] = $s
}

# ---------- 3) Benutzer laden (Grunddaten) ----------
Write-Host "Lade Benutzer..." -ForegroundColor Cyan
try {
  # -All holt alle Seiten via SDK
  $users = Get-MgUser -All -Property Id,DisplayName,UserPrincipalName
} catch {
  Write-Error "Get-MgUser fehlgeschlagen: $($_.Exception.Message)"
  exit 1
}

# ---------- 4) Group-Name-Cache ----------
$groupNameCache = @{}
function Resolve-GroupName {
  param([Parameter(Mandatory=$true)][string]$GroupId)
  if ($groupNameCache.ContainsKey($GroupId)) { return $groupNameCache[$GroupId] }
  try {
    $g = Get-MgGroup -GroupId $GroupId -Property Id,DisplayName
    $groupNameCache[$GroupId] = $g.DisplayName
  } catch {
    $groupNameCache[$GroupId] = $null
  }
  return $groupNameCache[$GroupId]
}

# ---------- 5) licenseAssignmentStates je Benutzer via v1.0 holen ----------
Write-Host "Ermittle Lizenzzuweisungen (direct vs group)..." -ForegroundColor Cyan
$rows = New-Object System.Collections.Generic.List[object]

# Fortschrittsanzeige
$idx = 0
$total = $users.Count

foreach ($u in $users) {
  $idx++
  Write-Progress -Activity "Analysiere Benutzer-Lizenzen" -Status "$($u.UserPrincipalName)" -PercentComplete (($idx/$total)*100)

  try {
    # v1.0 reicht für licenseAssignmentStates
    $resp = Invoke-MgGraphRequest -Method GET -Uri "/v1.0/users/$($u.Id)?`$select=licenseAssignmentStates"
  } catch {
    Write-Warning "Lizenzstatus für $($u.UserPrincipalName) konnte nicht gelesen werden: $($_.Exception.Message)"
    continue
  }

  $states = $resp.licenseAssignmentStates
  if (-not $states) { continue }

  foreach ($las in $states) {
    $skuId = [string]$las.skuId
    if (-not $skuId) { continue }
    if (-not $skuById.ContainsKey($skuId)) { continue } # ignorieren, wenn nicht gefilterte/gewünschte Lizenz
    $isGroup  = [bool]$las.assignedByGroup
    $groupId  = if ($isGroup) { [string]$las.assignedByGroup } else { $null }
    $group    = if ($groupId) { Resolve-GroupName -GroupId $groupId } else { $null }

    $rows.Add([pscustomobject]@{
      SkuPartNumber     = $skuById[$skuId].SkuPartNumber
      SkuId             = $skuId
      AssignmentType    = $(if ($isGroup) { "Group" } else { "Direct" })
      UserPrincipalName = $u.UserPrincipalName
      UserDisplayName   = $u.DisplayName
      GroupDisplayName  = $group
      GroupId           = $groupId
    })
  }
}

# ---------- 6) Ausgabe ----------
if (-not $rows -or $rows.Count -eq 0) {
  Write-Warning "Keine Lizenzzuweisungen für die ausgewählten SKUs gefunden."
  return
}

if ($OutFolder) {
  if (-not (Test-Path $OutFolder)) {
    New-Item -ItemType Directory -Path $OutFolder | Out-Null
  }
  $rows | Group-Object SkuPartNumber | ForEach-Object {
    $skuPn = $_.Name
    $file  = Join-Path $OutFolder ("{0}.csv" -f $skuPn)
    $_.Group |
      Sort-Object AssignmentType,UserPrincipalName |
      Select-Object SkuPartNumber,AssignmentType,UserPrincipalName,UserDisplayName,GroupDisplayName,GroupId,SkuId |
      Export-Csv -NoTypeInformation -Encoding UTF8 -Path $file
    Write-Host ("Exportiert: {0}" -f $file) -ForegroundColor Green
  }
} else {
  # Konsolenübersicht je Lizenz
  $rows | Group-Object SkuPartNumber | ForEach-Object {
    $skuPn = $_.Name
    Write-Host "`n=== $skuPn ===" -ForegroundColor Magenta

    $direct = $_.Group | Where-Object { $_.AssignmentType -eq "Direct" } | Sort-Object UserPrincipalName
    $group  = $_.Group | Where-Object { $_.AssignmentType -eq "Group"  } | Sort-Object GroupDisplayName,UserPrincipalName

    Write-Host "-- Direkt zugewiesen --" -ForegroundColor Yellow
    if ($direct) {
      $direct | Select-Object UserPrincipalName,UserDisplayName | Format-Table -AutoSize
    } else { Write-Host "(keine)" }

    Write-Host "-- Über Gruppe --" -ForegroundColor Yellow
    if ($group) {
      $group  | Select-Object GroupDisplayName,UserPrincipalName,UserDisplayName | Format-Table -AutoSize
    } else { Write-Host "(keine)" }
  }
}

Write-Host "`nFertig." -ForegroundColor Cyan
