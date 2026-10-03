#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Stellt den Zustand vor Install-EdepL1.ps1 aus einer Sicherung wieder her (EDEP-OPS-01).

.DESCRIPTION
    Stellt wieder her: Firewall-Konfiguration (vollständiger Import), Überwachungsrichtlinie,
    Telemetrie-Registrierungswerte, Starttyp von DiagTrack. Entfernt die von EDEP aktivierte
    App-Control-Richtlinie, sofern die Sicherung sie verzeichnet.

    Ohne -BackupPath wird die ÄLTESTE Sicherung verwendet, also der Zustand vor der ersten
    Anwendung von EDEP.

.EXAMPLE
    .\Restore-EdepL1.ps1 -WhatIf
.EXAMPLE
    .\Restore-EdepL1.ps1 -BackupPath 'C:\ProgramData\EDEP\backup\20260930-181500'
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param([string]$BackupPath)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'EdepStrings.ps1')
. (Join-Path $PSScriptRoot 'EdepL1.Common.ps1')

if (-not $BackupPath) {
    $oldest = Get-ChildItem -Path $EdepBackupRoot -Directory -ErrorAction SilentlyContinue |
        Where-Object { Test-Path (Join-Path $_.FullName 'manifest.json') } |
        Sort-Object Name | Select-Object -First 1
    if (-not $oldest) { throw "Keine Sicherung unter $EdepBackupRoot gefunden." }
    $BackupPath = $oldest.FullName
}

$manifestPath = Join-Path $BackupPath 'manifest.json'
$firewallPath = Join-Path $BackupPath 'firewall.wfw'
$auditPath    = Join-Path $BackupPath 'auditpol.csv'
foreach ($f in $manifestPath, $firewallPath, $auditPath) {
    if (-not (Test-Path -LiteralPath $f)) { throw "Sicherung unvollständig, fehlt: $f" }
}
$manifest = Get-Content $manifestPath -Raw | ConvertFrom-Json
Write-Host "Sicherung vom $($manifest.created) ($($manifest.computer))" -ForegroundColor Cyan

if ($PSCmdlet.ShouldProcess('Windows-Firewall', "Import aus $firewallPath")) {
    & netsh.exe advfirewall import $firewallPath | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Firewall-Import fehlgeschlagen.' }
}

if ($PSCmdlet.ShouldProcess('Überwachungsrichtlinie', "Wiederherstellen aus $auditPath")) {
    & auditpol.exe /restore /file:$auditPath | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'auditpol /restore fehlgeschlagen.' }
}

if ($PSCmdlet.ShouldProcess('Telemetrie-Richtlinien', 'Vorherige Werte wiederherstellen')) {
    foreach ($r in $manifest.registry) {
        if ($r.Existed) {
            if (-not (Test-Path $r.Path)) { New-Item -Path $r.Path -Force | Out-Null }
            Set-ItemProperty -Path $r.Path -Name $r.Name -Value $r.Value -Type DWord
        }
        else {
            Remove-ItemProperty -Path $r.Path -Name $r.Name -ErrorAction SilentlyContinue
        }
    }
}

if ($manifest.diagTrackStartType -and (Get-Service -Name DiagTrack -ErrorAction SilentlyContinue)) {
    if ($PSCmdlet.ShouldProcess('DiagTrack', "Starttyp $($manifest.diagTrackStartType)")) {
        Set-Service -Name DiagTrack -StartupType $manifest.diagTrackStartType
    }
}

# App-Control-Richtlinien stehen in jeder Sicherung, die sie angelegt hat — alle entfernen.
$policyIds = Get-ChildItem -Path $EdepBackupRoot -Directory -ErrorAction SilentlyContinue |
    ForEach-Object { Join-Path $_.FullName 'manifest.json' } |
    Where-Object { Test-Path $_ } |
    ForEach-Object { (Get-Content $_ -Raw | ConvertFrom-Json).appControlPolicyId } |
    Where-Object { $_ } | Sort-Object -Unique
foreach ($id in $policyIds) {
    if ($PSCmdlet.ShouldProcess("App-Control-Richtlinie $id", 'Entfernen')) {
        & CiTool.exe --remove-policy $id -json | Out-Null
        # -2147024894 = 0x80070002 (nicht gefunden): schon entfernt, kein Fehler (Lauf 1, Abweichung 5)
        if ($LASTEXITCODE -ne 0 -and $LASTEXITCODE -ne -2147024894) { Write-Warning "CiTool --remove-policy ${id}: Exit $LASTEXITCODE" }
    }
}

# Update-Domainregeln (-AllowWindowsUpdate): Die Firewall-Sicherung enthält die Schlüsselwörter nicht, sie werden
# hier entfernt. Den Netzwerkschutz stellt nur zurück, wer ihn selbst geändert hat (in irgendeiner Sicherung vermerkt).
$allManifests = Get-ChildItem -Path $EdepBackupRoot -Directory -ErrorAction SilentlyContinue |
    ForEach-Object { Join-Path $_.FullName 'manifest.json' } | Where-Object { Test-Path $_ } |
    ForEach-Object { Get-Content $_ -Raw | ConvertFrom-Json }
$hasKeywords = $false
if (Get-Command Get-NetFirewallDynamicKeywordAddress -ErrorAction SilentlyContinue) {
    $hasKeywords = @(Select-EdepUpdateKeyword (Get-NetFirewallDynamicKeywordAddress -AllAutoResolve -ErrorAction SilentlyContinue)).Count -gt 0
}
if ($hasKeywords -and $PSCmdlet.ShouldProcess('Update-Domain-Schlüsselwörter', 'Entfernen')) {
    Remove-EdepUpdateKeyword
}
$npRestore = Get-EdepNetworkProtectionRestoreValue $allManifests
if ($null -ne $npRestore -and (Get-EdepNetworkProtection) -ne $npRestore -and
    $PSCmdlet.ShouldProcess('Netzwerkschutz', "Zurück auf $(Get-EdepNetworkProtectionName $npRestore)")) {
    try { Set-MpPreference -EnableNetworkProtection (Get-EdepNetworkProtectionName $npRestore) -ErrorAction Stop }
    catch {
        Write-Warning ("Der Netzwerkschutz konnte nicht zurückgestellt werden (Defender nicht erreichbar: $($_.FullyQualifiedErrorId)). " +
            "Bitte später nachholen: Set-MpPreference -EnableNetworkProtection $(Get-EdepNetworkProtectionName $npRestore)")
    }
}

# Rücknahme dauerhaft machen (E-76): Registrierung und Dateisystem auf den Datenträger schreiben, damit ein harter Neustart
# direkt danach keine Werte zurückbringt.
if (-not $WhatIfPreference) {
    $persist = Invoke-EdepFlushRegistry
    if ($persist.Failed.Count) { Write-Warning ("Rücknahme konnte nicht vollständig auf den Datenträger geschrieben werden: " + ($persist.Failed -join ', ')) }
}

Write-Host ''
if ($WhatIfPreference) { Write-Host 'WhatIf: Es wurde nichts geändert.' -ForegroundColor Yellow; return }
Write-Host 'Wiederherstellung abgeschlossen. Ein Neustart wird empfohlen (App Control, Dienste).' -ForegroundColor Green
