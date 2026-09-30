# EDEP-Modul: lädt die gemeinsamen Definitionen, die L1-Prüfungen und das Audit.
. (Join-Path $PSScriptRoot 'EdepStrings.ps1')
. (Join-Path $PSScriptRoot 'EdepL1.Common.ps1')
. (Join-Path $PSScriptRoot 'EdepL1.Checks.ps1')
. (Join-Path $PSScriptRoot 'EdepAudit.ps1')

Export-ModuleMember -Function Invoke-EdepAudit, Get-EdepL1CheckResult
