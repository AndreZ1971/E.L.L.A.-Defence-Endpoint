#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Wendet das E.D. Endpoint Profile (EDEP) Stufe L1 mit Windows-Bordmitteln an.

.DESCRIPTION
    Standard ist der Audit-Modus (EDEP-OPS-02): Alle Regeln, Protokollierung und
    Telemetrie-Richtlinien werden gesetzt, die ausgehende Standardaktion bleibt aber
    "Allow". Erst mit -Enforce wird ausgehender Verkehr standardmäßig blockiert
    (EDEP-NET-03) — dann haben nur noch Programme mit Erlaubnisregel Netzwerkzugriff.

    Vor jeder Änderung wird der Zustand gesichert (EDEP-OPS-01). Rückgängig machen:
        .\Restore-EdepL1.ps1 -BackupPath <Pfad aus der Ausgabe>

.PARAMETER Enforce
    Setzt die ausgehende Standardaktion auf Block. Ohne -AllowProgram verlieren
    Browser und alle übrigen Programme ohne eigene Erlaubnisregel den Netzzugang.

.PARAMETER AllowProgram
    Vollständige Pfade zu Programmen, die ausgehend kommunizieren dürfen (z. B. Browser).
    Hinweis: Auf L1 kennt die Windows-Firewall nur Pfade, keine Signaturen. Die
    kryptografische Bindung (EDEP-ID-03) ist Aufgabe von L2.

.PARAMETER DeployAppControlAudit
    Aktiviert die Microsoft-Beispielrichtlinie "DefaultWindows_Audit" für App Control
    for Business im Audit-Modus (EDEP-ID-01). Blockiert nichts, protokolliert nur.

.PARAMETER DisableDiagTrack
    Deaktiviert zusätzlich den Dienst DiagTrack (EDEP-TEL-05, auf L1 optional).

.EXAMPLE
    .\Install-EdepL1.ps1 -DeployAppControlAudit -WhatIf
    Zeigt nur an, was geändert würde.

.EXAMPLE
    .\Install-EdepL1.ps1 -Enforce -DeployAppControlAudit `
        -AllowProgram "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe"
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [switch]$Enforce,
    [string[]]$AllowProgram = @(),
    [switch]$DeployAppControlAudit,
    [switch]$DisableDiagTrack
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'EdepL1.Common.ps1')

function Write-Step([string]$Text) { Write-Host "==> $Text" -ForegroundColor Cyan }

foreach ($p in $AllowProgram) {
    if (-not (Test-Path -LiteralPath $p)) { throw "AllowProgram nicht gefunden: $p" }
    # EDEP-NET-10: Eine Freigabe für einen von Benutzern änderbaren Pfad wäre eine Hintertür (Umgehung B-04).
    $why = @(Get-EdepWritableByNonAdmin $p)
    if ($why.Count) {
        # Als Administrator ist jede ACL lesbar; "UNBEKANNT" wird daher ebenfalls abgelehnt.
        throw ("AllowProgram '$p' ist für Nicht-Administratoren änderbar und darf nicht freigegeben werden (EDEP-NET-10):`n  " +
            ($why -join "`n  ") + "`nProgramm systemweit (z. B. unter C:\Program Files) installieren und erneut versuchen.")
    }
}

if ($Enforce -and $AllowProgram.Count -eq 0) {
    Write-Warning ('-Enforce ohne -AllowProgram: Browser und alle Programme ohne eigene ' +
        'Erlaubnisregel verlieren den Netzzugang. Store-Apps mit eigenen Windows-Regeln bleiben erreichbar.')
}

# ---------------------------------------------------------------------------
# 1. Sicherung (EDEP-OPS-01)
# ---------------------------------------------------------------------------
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$backupPath = Join-Path $EdepBackupRoot $stamp

$firstBackup = Get-ChildItem -Path $EdepBackupRoot -Directory -ErrorAction SilentlyContinue |
    Where-Object { Test-Path (Join-Path $_.FullName 'manifest.json') } |
    Sort-Object Name | Select-Object -First 1
if ($firstBackup) {
    Write-Warning ("EDEP L1 wurde schon einmal angewendet. Der Zustand VOR EDEP liegt in der ältesten " +
        "Sicherung: $($firstBackup.FullName)")
}

if ($PSCmdlet.ShouldProcess($backupPath, 'Aktuellen Zustand sichern')) {
    Write-Step "Sichere aktuellen Zustand nach $backupPath"
    New-Item -ItemType Directory -Path $backupPath -Force | Out-Null

    & netsh.exe advfirewall export (Join-Path $backupPath 'firewall.wfw') | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Firewall-Export fehlgeschlagen.' }

    & auditpol.exe /backup /file:(Join-Path $backupPath 'auditpol.csv') | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Sicherung der Überwachungsrichtlinie fehlgeschlagen.' }

    $registryBackup = foreach ($s in $EdepRegistrySettings) {
        $current = Get-ItemProperty -Path $s.Path -Name $s.Name -ErrorAction SilentlyContinue
        [pscustomobject]@{
            Path    = $s.Path
            Name    = $s.Name
            Existed = [bool]$current
            Value   = if ($current) { $current.($s.Name) } else { $null }
        }
    }

    $diagTrack = Get-Service -Name DiagTrack -ErrorAction SilentlyContinue
    $manifest = [ordered]@{
        edep              = $EdepVersion
        created           = (Get-Date).ToString('o')
        computer          = $env:COMPUTERNAME
        enforce           = [bool]$Enforce
        registry          = @($registryBackup)
        diagTrackStartType = if ($diagTrack) { [string]$diagTrack.StartType } else { $null }
        appControlPolicyId = $null
    }
    $manifest | ConvertTo-Json -Depth 5 | Set-Content -Path (Join-Path $backupPath 'manifest.json') -Encoding UTF8
}

# ---------------------------------------------------------------------------
# 2. Firewall-Profile (EDEP-NET-01, -02, -03, EDEP-LOG-01)
# ---------------------------------------------------------------------------
$outbound = if ($Enforce) { 'Block' } else { 'Allow' }
if ($PSCmdlet.ShouldProcess('Alle Firewall-Profile', "Aktivieren, Inbound=Block, Outbound=$outbound, LogBlocked")) {
    Write-Step "Firewall-Profile: eingehend Block, ausgehend $outbound, Protokollierung verworfener Pakete"
    Set-NetFirewallProfile -Profile Domain, Private, Public `
        -Enabled True `
        -DefaultInboundAction Block `
        -DefaultOutboundAction $outbound `
        -LogBlocked True `
        -LogMaxSizeKilobytes 16384

    foreach ($key in $FirewallProfileKeys.Values) {
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\$key"
        $v = Get-ItemProperty -Path $regPath -Name DisableStealthMode -ErrorAction SilentlyContinue
        if ($v -and $v.DisableStealthMode -ne 0) {
            Set-ItemProperty -Path $regPath -Name DisableStealthMode -Value 0 -Type DWord
        }
    }
}

# ---------------------------------------------------------------------------
# 3. Regeln (Gruppe EDEP-L1, idempotent)
# ---------------------------------------------------------------------------
if ($PSCmdlet.ShouldProcess("Regelgruppe $EdepRuleGroup", 'Neu anlegen')) {
    Write-Step "Lege Regelgruppe $EdepRuleGroup neu an"
    Get-NetFirewallRule -Group $EdepRuleGroup -ErrorAction SilentlyContinue | Remove-NetFirewallRule

    $common = @{ Group = $EdepRuleGroup; Enabled = 'True'; Profile = 'Any' }

    # Kernnetzwerk (DNS-Client, DHCP, NDP) muss ausgehend erlaubt sein.
    Get-NetFirewallRule -Group $CoreNetworkingGroup -Direction Outbound -ErrorAction SilentlyContinue |
        Enable-NetFirewallRule

    # EDEP-TEL-04: Update-relevante Dienste über Dienst-SID (EDEP-ID-05).
    foreach ($svc in $EdepRequiredServices) {
        New-NetFirewallRule @common -Direction Outbound -Action Allow `
            -DisplayName "EDEP L1 - Dienst $($svc.Name) (EDEP-TEL-04)" `
            -Service $svc.Name -Protocol $svc.Protocol -RemotePort $svc.Ports | Out-Null
    }

    # Defender und SmartScreen (Cloud-Schutz, Reputationsprüfung).
    foreach ($exe in Get-EdepDefenderPrograms) {
        New-NetFirewallRule @common -Direction Outbound -Action Allow `
            -DisplayName "EDEP L1 - Schutz $(Split-Path $exe -Leaf) (EDEP-TEL-04)" `
            -Program $exe -Protocol TCP -RemotePort 80, 443 | Out-Null
    }

    # Vom Nutzer zugelassene Programme.
    foreach ($exe in $AllowProgram) {
        $full = (Resolve-Path -LiteralPath $exe).ProviderPath
        New-NetFirewallRule @common -Direction Outbound -Action Allow `
            -DisplayName "EDEP L1 - Erlaubt $(Split-Path $full -Leaf)" `
            -Program $full | Out-Null
    }

    # EDEP-NET-04: LOLBins ausgehend blockieren (Blockregeln haben Vorrang).
    foreach ($exe in Get-EdepLolbinPaths) {
        New-NetFirewallRule @common -Direction Outbound -Action Block `
            -DisplayName "EDEP L1 - LOLBin $(Split-Path $exe -Leaf) (EDEP-NET-04)" `
            -Program $exe | Out-Null
    }

    # EDEP-TEL-02: Telemetrie-Dienste ausgehend blockieren.
    foreach ($svc in $EdepTelemetryServices) {
        if (Get-Service -Name $svc -ErrorAction SilentlyContinue) {
            New-NetFirewallRule @common -Direction Outbound -Action Block `
                -DisplayName "EDEP L1 - Telemetrie $svc (EDEP-TEL-02)" `
                -Service $svc | Out-Null
        }
    }

    # EDEP-NET-05: SMB/RDP/WinRM/RPC eingehend im Profil Public sperren.
    New-NetFirewallRule -Group $EdepRuleGroup -Enabled True -Profile Public -Direction Inbound -Action Block `
        -DisplayName 'EDEP L1 - Public: SMB/RDP/WinRM/RPC eingehend (EDEP-NET-05)' `
        -Protocol TCP -LocalPort $EdepPublicInboundBlockPorts | Out-Null
}

# ---------------------------------------------------------------------------
# 4. Telemetrie-Richtlinien (EDEP-TEL-01, -03)
# ---------------------------------------------------------------------------
if ($PSCmdlet.ShouldProcess('Telemetrie-Richtlinien (HKLM\SOFTWARE\Policies)', 'Setzen')) {
    Write-Step 'Setze Telemetrie-Richtlinien'
    foreach ($s in $EdepRegistrySettings) {
        if (-not (Test-Path $s.Path)) { New-Item -Path $s.Path -Force | Out-Null }
        Set-ItemProperty -Path $s.Path -Name $s.Name -Value $s.Value -Type DWord
    }
    $ed = Get-EdepEditionSupportsSecurityTelemetry
    if (-not $ed.Supported) {
        Write-Warning ("Edition '$($ed.EditionId)': AllowTelemetry=0 wirkt wie 1 (Required). " +
            'Das ist die niedrigste Stufe, die diese Edition zulässt (EDEP-TEL-01).')
    }
}

# ---------------------------------------------------------------------------
# 5. Überwachung "Filterplattformverbindung" (EDEP-LOG-01)
# ---------------------------------------------------------------------------
if ($PSCmdlet.ShouldProcess('Überwachungsrichtlinie', 'Filterplattformverbindung: Fehler protokollieren')) {
    Write-Step 'Aktiviere Ereignis 5157 (blockierte Verbindungen)'
    & auditpol.exe /set /subcategory:$AuditFilteringPlatformConnection /failure:enable | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'auditpol /set fehlgeschlagen.' }
}

# ---------------------------------------------------------------------------
# 6. Optional: DiagTrack deaktivieren (EDEP-TEL-05)
# ---------------------------------------------------------------------------
if ($DisableDiagTrack -and (Get-Service -Name DiagTrack -ErrorAction SilentlyContinue)) {
    if ($PSCmdlet.ShouldProcess('DiagTrack', 'Dienst stoppen und deaktivieren')) {
        Write-Step 'Deaktiviere Dienst DiagTrack'
        Stop-Service -Name DiagTrack -Force -ErrorAction SilentlyContinue
        Set-Service -Name DiagTrack -StartupType Disabled
    }
}

# ---------------------------------------------------------------------------
# 7. Optional: App Control for Business im Audit-Modus (EDEP-ID-01)
# ---------------------------------------------------------------------------
if ($DeployAppControlAudit) {
    $template = "$env:SystemRoot\schemas\CodeIntegrity\ExamplePolicies\DefaultWindows_Audit.xml"
    if (-not (Test-Path $template)) { throw "Vorlage fehlt: $template" }
    if ($PSCmdlet.ShouldProcess('App Control for Business', 'Richtlinie DefaultWindows_Audit aktivieren')) {
        Write-Step 'Aktiviere App-Control-Richtlinie (Audit)'
        $xml = Join-Path $backupPath 'EDEP-L1-AppControl-Audit.xml'
        Copy-Item $template $xml
        $policyId = Set-CIPolicyIdInfo -FilePath $xml -PolicyName 'EDEP L1 Audit' -ResetPolicyID
        $policyId = ([regex]::Match([string]$policyId, '\{[0-9A-Fa-f-]{36}\}')).Value
        Set-RuleOption -FilePath $xml -Option 3   # Enabled:Audit Mode (sicherstellen)
        $cip = Join-Path $backupPath "$policyId.cip"
        ConvertFrom-CIPolicy -XmlFilePath $xml -BinaryFilePath $cip | Out-Null
        & CiTool.exe --update-policy $cip -json | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "CiTool --update-policy fehlgeschlagen (Exit $LASTEXITCODE)." }

        $manifestPath = Join-Path $backupPath 'manifest.json'
        $m = Get-Content $manifestPath -Raw | ConvertFrom-Json
        $m.appControlPolicyId = $policyId
        $m | ConvertTo-Json -Depth 5 | Set-Content -Path $manifestPath -Encoding UTF8
    }
}

# ---------------------------------------------------------------------------
Write-Host ''
if ($WhatIfPreference) {
    Write-Host 'WhatIf: Es wurde nichts geändert.' -ForegroundColor Yellow
    return
}
Write-Host "EDEP L1 angewendet (Modus: $(if ($Enforce) { 'ENFORCE' } else { 'AUDIT' }))." -ForegroundColor Green
Write-Host "Sicherung:      $backupPath"
Write-Host "Prüfen:         .\Test-EdepL1.ps1"
Write-Host "Rückgängig:     .\Restore-EdepL1.ps1 -BackupPath '$backupPath'"
if (-not $Enforce) {
    Write-Host ''
    Write-Host 'Audit-Modus: EDEP-NET-03 ist noch nicht erfüllt. Firewall-Log auswerten, dann mit -Enforce erneut ausführen.' -ForegroundColor Yellow
}
