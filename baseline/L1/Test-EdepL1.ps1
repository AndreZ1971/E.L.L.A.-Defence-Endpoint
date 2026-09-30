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
. (Join-Path $PSScriptRoot 'EdepL1.Checks.ps1')

$results = @(Get-EdepL1CheckResult)

$failed = @($results | Where-Object { $_.Status -in 'FAIL', 'UNKNOWN' }).Count
$passed = $results.Count - $failed
$summary = "EDEP $EdepVersion L1 — geprüft $(Get-Date -Format 'yyyy-MM-dd') — $passed/$($results.Count) erfüllt"

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
