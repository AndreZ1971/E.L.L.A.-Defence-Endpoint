#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Prüft die Konformität dieses Systems mit EDEP Stufe L1. Ändert nichts.

.DESCRIPTION
    Geprüft wird der WIRKSAME Zustand (ActiveStore), also inklusive Gruppenrichtlinien.
    Ergebnis je Anforderung: PASS, WARN (erfüllt, mit Hinweis) oder FAIL.
    Exit-Code 0 nur, wenn keine Anforderung FAIL ist.

.PARAMETER Json
    Gibt das Prüfprotokoll als JSON aus (für Konformitätsnachweise, SPEC.md Abschnitt 5).

.EXAMPLE
    .\Test-EdepL1.ps1
.EXAMPLE
    .\Test-EdepL1.ps1 -Json | Set-Content edep-l1-report.json
#>
[CmdletBinding()]
param([switch]$Json)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'EdepL1.Common.ps1')

$results = [System.Collections.Generic.List[object]]::new()
function Add-Result([string]$Id, [string]$Status, [string]$Detail) {
    $results.Add([pscustomobject]@{ Id = $Id; Status = $Status; Detail = $Detail })
}

$profiles = Get-NetFirewallProfile -PolicyStore ActiveStore

function Test-EdepProfileMatch($Rule, [string]$ProfileName) {
    $p = [string]$Rule.Profile
    ($p -match 'Any') -or ($p -match $ProfileName)
}

# --- EDEP-NET-01 -----------------------------------------------------------
$bad = $profiles | Where-Object { -not $_.Enabled -or [string]$_.DefaultInboundAction -ne 'Block' }
if ($bad) { Add-Result 'EDEP-NET-01' 'FAIL' "Nicht aktiv oder eingehend nicht Block: $($bad.Name -join ', ')" }
else { Add-Result 'EDEP-NET-01' 'PASS' 'Alle Profile aktiv, eingehend Block' }

# --- EDEP-NET-02 -----------------------------------------------------------
$stealthOff = foreach ($name in $FirewallProfileKeys.Keys) {
    $key = $FirewallProfileKeys[$name]
    foreach ($root in "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\$key",
                      "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\$key") {
        $v = Get-ItemProperty -Path $root -Name DisableStealthMode -ErrorAction SilentlyContinue
        if ($v -and $v.DisableStealthMode -ne 0) { "$name ($root)" }
    }
}
if ($stealthOff) { Add-Result 'EDEP-NET-02' 'FAIL' "Stealth-Modus deaktiviert: $($stealthOff -join '; ')" }
else { Add-Result 'EDEP-NET-02' 'PASS' 'Stealth-Modus aktiv (Standard)' }

# --- EDEP-NET-03 -----------------------------------------------------------
$bad = $profiles | Where-Object { [string]$_.DefaultOutboundAction -ne 'Block' }
if ($bad) { Add-Result 'EDEP-NET-03' 'FAIL' "Ausgehend nicht Block: $($bad.Name -join ', ') (Audit-Modus?)" }
else {
    $allowCount = (Get-NetFirewallRule -PolicyStore ActiveStore -Direction Outbound -Action Allow -Enabled True -ErrorAction SilentlyContinue | Measure-Object).Count
    Add-Result 'EDEP-NET-03' 'PASS' "Ausgehend Block in allen Profilen; $allowCount aktive ausgehende Erlaubnisregeln"
}

# Ausgehende Blockregeln einmal einsammeln (Programm- und Dienstfilter).
$outBlock = @(Get-NetFirewallRule -PolicyStore ActiveStore -Direction Outbound -Action Block -Enabled True -ErrorAction SilentlyContinue)
$blockedPrograms = @($outBlock | Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue |
    ForEach-Object { ConvertTo-EdepComparablePath $_.Program })
$blockedServices = @($outBlock | Get-NetFirewallServiceFilter -ErrorAction SilentlyContinue |
    ForEach-Object { ([string]$_.Service).ToLowerInvariant() })

# --- EDEP-NET-04 -----------------------------------------------------------
$missing = Get-EdepLolbinPaths | Where-Object { $blockedPrograms -notcontains (ConvertTo-EdepComparablePath $_) }
if ($missing) { Add-Result 'EDEP-NET-04' 'FAIL' "Ohne ausgehende Blockregel: $(($missing | ForEach-Object { $_.Substring($env:SystemRoot.Length + 1) }) -join ', ')" }
else { Add-Result 'EDEP-NET-04' 'PASS' "$(@(Get-EdepLolbinPaths).Count) LOLBins ausgehend blockiert" }

# --- EDEP-NET-05 -----------------------------------------------------------
$inBlockPublic = @(Get-NetFirewallRule -PolicyStore ActiveStore -Direction Inbound -Action Block -Enabled True -ErrorAction SilentlyContinue |
    Where-Object { Test-EdepProfileMatch $_ 'Public' })
$blockedPorts = @($inBlockPublic | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue |
    Where-Object { [string]$_.Protocol -in 'TCP', 'Any' } |
    ForEach-Object { $_.LocalPort } | ForEach-Object { [string]$_ })
$missing = $EdepPublicInboundBlockPorts | Where-Object { ($blockedPorts -notcontains $_) -and ($blockedPorts -notcontains 'Any') }
if ($missing) { Add-Result 'EDEP-NET-05' 'FAIL' "Public eingehend nicht gesperrt: TCP $($missing -join ', ')" }
else { Add-Result 'EDEP-NET-05' 'PASS' "Public eingehend gesperrt: TCP $($EdepPublicInboundBlockPorts -join ', ')" }

# --- EDEP-ID-01 ------------------------------------------------------------
try {
    $raw = Invoke-EdepNative { CiTool.exe --list-policies -json } | Out-String
    $ci = $raw | ConvertFrom-Json -ErrorAction Stop
    if ($ci.OperationResult -eq -2147024891) { throw "Zugriff verweigert (Adminrechte nötig)" }
    if ($null -eq $ci.Policies) { throw "Unerwartete CiTool-Ausgabe (OperationResult=$($ci.OperationResult))" }
    $active = @($ci.Policies | Where-Object { $_.IsEnforced -and -not $_.IsSystemPolicy })
    if ($active.Count -eq 0) {
        Add-Result 'EDEP-ID-01' 'FAIL' 'Keine aktive, nicht-systemeigene App-Control-Richtlinie'
    }
    else {
        $names = ($active | ForEach-Object {
            $mode = if ((@($_.PolicyOptions) -join ' ') -match 'Audit') { 'Audit' } else { 'Erzwingend' }
            "$($_.FriendlyName) [$mode]"
        }) -join '; '
        Add-Result 'EDEP-ID-01' 'PASS' "Aktiv: $names"
    }
}
catch { Add-Result 'EDEP-ID-01' 'FAIL' "App-Control-Status nicht ermittelbar: $($_.Exception.Message)" }

# --- EDEP-TEL-01 -----------------------------------------------------------
$tel = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' -Name AllowTelemetry -ErrorAction SilentlyContinue
$ed = Get-EdepEditionSupportsSecurityTelemetry
if (-not $tel) { Add-Result 'EDEP-TEL-01' 'FAIL' 'Richtlinie AllowTelemetry nicht gesetzt' }
elseif ($tel.AllowTelemetry -eq 0 -and $ed.Supported) { Add-Result 'EDEP-TEL-01' 'PASS' 'AllowTelemetry=0, wirksam: Security' }
elseif ($tel.AllowTelemetry -eq 0) { Add-Result 'EDEP-TEL-01' 'WARN' "AllowTelemetry=0, wirksam auf '$($ed.EditionId)': 1 (Required) — niedrigste Stufe dieser Edition" }
elseif ($tel.AllowTelemetry -eq 1 -and -not $ed.Supported) { Add-Result 'EDEP-TEL-01' 'PASS' "AllowTelemetry=1 (Required), niedrigste Stufe für '$($ed.EditionId)'" }
else { Add-Result 'EDEP-TEL-01' 'FAIL' "AllowTelemetry=$($tel.AllowTelemetry) ist nicht die niedrigste Stufe" }

# --- EDEP-TEL-02 -----------------------------------------------------------
$missing = $EdepTelemetryServices |
    Where-Object { (Get-Service -Name $_ -ErrorAction SilentlyContinue) -and ($blockedServices -notcontains $_.ToLowerInvariant()) }
if ($missing) { Add-Result 'EDEP-TEL-02' 'FAIL' "Ohne ausgehende Blockregel: $($missing -join ', ')" }
else { Add-Result 'EDEP-TEL-02' 'PASS' "Ausgehend blockiert: $($EdepTelemetryServices -join ', ')" }

# --- EDEP-TEL-03 -----------------------------------------------------------
$wrong = $EdepRegistrySettings | Where-Object { $_.Id -eq 'EDEP-TEL-03' } | Where-Object {
    $v = Get-ItemProperty -Path $_.Path -Name $_.Name -ErrorAction SilentlyContinue
    -not $v -or $v.($_.Name) -ne $_.Value
}
if ($wrong) { Add-Result 'EDEP-TEL-03' 'FAIL' "Nicht gesetzt: $(($wrong | ForEach-Object { $_.Name }) -join ', ')" }
else { Add-Result 'EDEP-TEL-03' 'PASS' 'Werbe-ID und Aktivitätsverlauf per Richtlinie deaktiviert' }

# --- EDEP-TEL-04 -----------------------------------------------------------
$problems = @()
$outboundBlocked = @($profiles | Where-Object { [string]$_.DefaultOutboundAction -eq 'Block' }).Count -gt 0
$allowServices = @()
if ($outboundBlocked) {
    $allowServices = @(Get-NetFirewallRule -PolicyStore ActiveStore -Direction Outbound -Action Allow -Enabled True -ErrorAction SilentlyContinue |
        Get-NetFirewallServiceFilter -ErrorAction SilentlyContinue | ForEach-Object { ([string]$_.Service).ToLowerInvariant() })
}
foreach ($svc in $EdepRequiredServices) {
    $n = $svc.Name.ToLowerInvariant()
    if ($blockedServices -contains $n) { $problems += "$($svc.Name) blockiert" }
    elseif ($outboundBlocked -and ($allowServices -notcontains $n)) { $problems += "$($svc.Name) ohne Erlaubnisregel" }
}
$defenderExe = Get-EdepDefenderPrograms | Select-Object -First 1
if ($outboundBlocked -and $defenderExe) {
    $allowPrograms = @(Get-NetFirewallRule -PolicyStore ActiveStore -Direction Outbound -Action Allow -Enabled True -ErrorAction SilentlyContinue |
        Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue | ForEach-Object { ConvertTo-EdepComparablePath $_.Program })
    if ($allowPrograms -notcontains (ConvertTo-EdepComparablePath $defenderExe)) {
        $problems += 'Defender-Plattform aktualisiert, Regel veraltet (Install-EdepL1.ps1 erneut ausführen)'
    }
}
if ($problems) { Add-Result 'EDEP-TEL-04' 'FAIL' ($problems -join '; ') }
else { Add-Result 'EDEP-TEL-04' 'PASS' 'Update- und Schutzdienste erreichbar' }

# --- EDEP-LOG-01 -----------------------------------------------------------
$problems = @()
$bad = $profiles | Where-Object { [string]$_.LogBlocked -ne 'True' }
if ($bad) { $problems += "LogBlocked aus: $($bad.Name -join ', ')" }
# Das /backup-Format enthält die sprachunabhängige Spalte "Setting Value" (Spalte 7):
# 0 keine, 1 Erfolg, 2 Fehler, 3 beides. Die Sicherung wird nur gelesen und danach gelöscht.
$auditTmp = Join-Path ([IO.Path]::GetTempPath()) "edep-auditpol-$PID.csv"
Invoke-EdepNative { auditpol.exe /backup /file:$auditTmp } | Out-Null
if ($LASTEXITCODE -ne 0 -or -not (Test-Path $auditTmp)) { $problems += 'auditpol nicht lesbar' }
else {
    $guid = $AuditFilteringPlatformConnection.Trim('{}')
    $row = Get-Content $auditTmp | Where-Object { $_ -match [regex]::Escape($guid) } | Select-Object -First 1
    Remove-Item $auditTmp -Force -ErrorAction SilentlyContinue
    $value = if ($row) { [int](($row -split ',')[6]) } else { 0 }
    if (($value -band 2) -eq 0) { $problems += 'Ereignis 5157 (Fehler) nicht aktiviert' }
}
if ($problems) { Add-Result 'EDEP-LOG-01' 'FAIL' ($problems -join '; ') }
else { Add-Result 'EDEP-LOG-01' 'PASS' 'Firewall-Log und Ereignis 5157 aktiv' }

# --- EDEP-LOG-02 -----------------------------------------------------------
$remote = $profiles | Where-Object { ([Environment]::ExpandEnvironmentVariables([string]$_.LogFileName)) -like '\\*' }
if ($remote) { Add-Result 'EDEP-LOG-02' 'FAIL' "Firewall-Log auf Netzwerkpfad: $($remote.Name -join ', ')" }
else { Add-Result 'EDEP-LOG-02' 'PASS' 'Firewall-Log lokal' }

# --- EDEP-OPS-01 -----------------------------------------------------------
$backup = Get-ChildItem -Path $EdepBackupRoot -Directory -ErrorAction SilentlyContinue |
    Where-Object { (Test-Path (Join-Path $_.FullName 'manifest.json')) -and (Test-Path (Join-Path $_.FullName 'firewall.wfw')) } |
    Sort-Object Name | Select-Object -First 1
if ($backup) { Add-Result 'EDEP-OPS-01' 'PASS' "Sicherung vorhanden: $($backup.FullName)" }
else { Add-Result 'EDEP-OPS-01' 'FAIL' "Keine Sicherung unter $EdepBackupRoot" }

# ---------------------------------------------------------------------------
$failed = @($results | Where-Object Status -eq 'FAIL').Count
$passed = $results.Count - $failed
$summary = "EDEP $EdepVersion L1 — geprüft $(Get-Date -Format 'yyyy-MM-dd') — $passed/$($results.Count) PASS"

if ($Json) {
    [ordered]@{
        profile  = 'EDEP'
        version  = $EdepVersion
        level    = 'L1'
        computer = $env:COMPUTERNAME
        checked  = (Get-Date).ToString('o')
        summary  = $summary
        conform  = ($failed -eq 0)
        results  = $results
    } | ConvertTo-Json -Depth 4
}
else {
    foreach ($r in $results) {
        $color = switch ($r.Status) { 'PASS' { 'Green' } 'WARN' { 'Yellow' } default { 'Red' } }
        Write-Host ('{0,-5} {1,-12} {2}' -f $r.Status, $r.Id, $r.Detail) -ForegroundColor $color
    }
    Write-Host ''
    Write-Host $summary -ForegroundColor $(if ($failed -eq 0) { 'Green' } else { 'Red' })
}

exit $(if ($failed -eq 0) { 0 } else { 1 })
