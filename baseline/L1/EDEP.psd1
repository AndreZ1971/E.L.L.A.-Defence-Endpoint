@{
    RootModule           = 'EDEP.psm1'
    ModuleVersion        = '0.1.0'
    GUID                 = '90145b76-da79-49ae-bc3f-8e6229343a1c'
    Author               = 'Andre Zabel'
    CompanyName          = 'Andre Zabel'
    Copyright            = '(c) 2026 Andre Zabel. MIT-Lizenz.'
    Description          = 'E.D. Endpoint Profile (EDEP): kostenloses Audit, wie offen ein Windows-System für Datenabfluss ist (ausgehender Verkehr, LOLBins, Telemetrie, Angriffsfläche), sowie Anwenden, Prüfen und Rücknahme von EDEP Stufe L1 mit Windows-Bordmitteln.'
    PowerShellVersion    = '5.1'
    CompatiblePSEditions = @('Desktop', 'Core')
    FunctionsToExport    = @('Invoke-EdepAudit', 'Get-EdepL1CheckResult')
    CmdletsToExport      = @()
    VariablesToExport    = @()
    AliasesToExport      = @()
    FileList             = @(
        'EDEP.psd1', 'EDEP.psm1', 'EdepStrings.ps1', 'EdepL1.Common.ps1', 'EdepL1.Checks.ps1', 'EdepAudit.ps1',
        'Invoke-EdepAudit.ps1', 'Install-EdepL1.ps1', 'Test-EdepL1.ps1', 'Restore-EdepL1.ps1'
    )
    PrivateData          = @{
        PSData = @{
            Tags         = @('Security', 'Firewall', 'Hardening', 'Audit', 'Windows', 'ZeroTrust', 'Telemetry', 'WFP', 'WDAC')
            LicenseUri   = 'https://github.com/AndreZ1971/E.L.L.A.-Defence-Endpoint/blob/main/LICENSE'
            ProjectUri   = 'https://github.com/AndreZ1971/E.L.L.A.-Defence-Endpoint'
            ReleaseNotes = 'Erste Version: Invoke-EdepAudit mit Punktzahl und HTML-Bericht; L1-Skripte.'
        }
    }
}
