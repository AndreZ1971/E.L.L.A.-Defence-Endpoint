<#
.SYNOPSIS
    Kostenloses EDEP-Audit: Wie offen ist dieses Windows-System für Datenabfluss? Ändert nichts.

.DESCRIPTION
    Aufruf ohne Modulinstallation. Entspricht Import-Module .\EDEP.psd1; Invoke-EdepAudit.
    Läuft ohne Adminrechte; als Administrator werden zusätzlich App Control, Überwachungs-
    richtlinie und Defender-Einstellungen geprüft.

.EXAMPLE
    .\Invoke-EdepAudit.ps1 -Open
.EXAMPLE
    .\Invoke-EdepAudit.ps1 -NoHtml -PassThru | ConvertTo-Json -Depth 5 | Set-Content edep-audit-report.json
#>
[CmdletBinding()]
param(
    [string]$OutputPath = (Get-Location).ProviderPath,
    [switch]$NoHtml,
    [switch]$Open,
    [switch]$PassThru
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'EDEP.psd1') -Force
Invoke-EdepAudit @PSBoundParameters
