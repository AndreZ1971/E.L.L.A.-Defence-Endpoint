#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Prüft die Konformität dieses Systems mit EDEP Stufe L1. Ändert nichts.

.DESCRIPTION
    Geprüft wird der WIRKSAME Zustand (ActiveStore), also inklusive Gruppenrichtlinien.
    Ergebnis je Anforderung: PASS, WARN (erfüllt, mit Hinweis), FAIL oder UNKNOWN.
    Exit-Code 0 nur, wenn keine Anforderung FAIL oder UNKNOWN ist.

    Für eine verständliche Bewertung mit Punktzahl und HTML-Bericht (auch ohne
    Adminrechte): Invoke-EdepAudit.ps1

.PARAMETER Language
    de oder en für die Detailtexte. Standard: Windows-Anzeigesprache.

.PARAMETER Json
    Gibt das Prüfprotokoll als JSON aus (für Konformitätsnachweise, SPEC.md Abschnitt 5).

.PARAMETER ProbeUpdates
    Misst bei EDEP-TEL-04 zusätzlich die Wirkung: Eine Update-Suche muss gelingen. Unter "ausgehend Block"
    ohne diesen Schalter meldet TEL-04 nur WARN, weil Regeln allein die Erreichbarkeit nicht belegen
    (Lauf 1, Abweichungen 6 und 7). Die Suche ändert nichts am System, braucht aber Netz und etwas Zeit.

.EXAMPLE
    .\Test-EdepL1.ps1
.EXAMPLE
    .\Test-EdepL1.ps1 -Json | Set-Content edep-l1-report.json
#>
[CmdletBinding()]
param(
    [switch]$Json,
    [switch]$ProbeUpdates,
    [ValidateSet('de', 'en')][string]$Language
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'EdepStrings.ps1')
. (Join-Path $PSScriptRoot 'EdepL1.Common.ps1')
. (Join-Path $PSScriptRoot 'EdepL1.Checks.ps1')
if ($Language) { Set-EdepLanguage $Language }

$results = @(Get-EdepL1CheckResult -ProbeUpdates:$ProbeUpdates)

$failed = @($results | Where-Object { $_.Status -in 'FAIL', 'UNKNOWN' }).Count
$passed = $results.Count - $failed
$summary = Get-EdepText 'l1.summary' @($EdepVersion, (Get-Date -Format 'yyyy-MM-dd'), $passed, $results.Count)

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
        Write-Host ('{0,-7} {1,-12} {2}' -f $r.Status, $r.Id, $r.Detail) -ForegroundColor $color
    }
    Write-Host ''
    Write-Host $summary -ForegroundColor $(if ($failed -eq 0) { 'Green' } else { 'Red' })
}

exit $(if ($failed -eq 0) { 0 } else { 1 })
