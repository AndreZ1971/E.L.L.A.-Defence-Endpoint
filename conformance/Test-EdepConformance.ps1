<#
.SYNOPSIS
    Ein Aufruf für Dritte: prüft Integrität des Standes, die L1-Anforderungen und das Audit und schreibt ein strukturiertes Protokoll (JSON).

.DESCRIPTION
    Ändert nichts am System. Das Protokoll hält fest, WAS GEMESSEN wurde. Es ist KEIN Konformitätsnachweis und
    macht keine Aussage über Tests, die hier nicht laufen (Angriffssimulationen "aktiv" und Prüfungen "Review"
    aus conformance/README.md); diese stehen im Protokoll unter "notRun".

    Schritte:
      1. Integrität: SHA256SUMS gegen die Dateien prüfen; Signatur (SHA256SUMS.sig) mit ssh-keygen prüfen (docs/SIGNING.md).
         Gilt für den ZIP-Stand eines Tags. Ein Klon unter Windows wandelt Zeilenenden um und meldet dann WARN.
      2. L1: dieselben 15 Prüfungen wie Test-EdepL1.ps1 (ohne Adminrechte sind einige "UNKNOWN").
      3. Audit: Punktzahl und Befunde (Invoke-EdepAudit, ohne HTML).
      4. Mit -Probe zusätzlich: Messung der Update-Erreichbarkeit (EDEP-TEL-04) und die Einheitentests (tools/Test-EdepUnits.ps1).
    5. Mit -Destructive -ConfirmDestructive: ÄNDERT DAS SYSTEM, nur in einer Test-VM. Install (Audit), Install (Enforce) mit
       Umgehungstests (curl.exe, umbenannte Kopie, BITS, Authenticated-Bypass-Regel, uneingeschränkte Regel, beschreibbarer Pfad),
       dann Restore und Fingerabdruck-Vergleich (conformance/EdepConformance.Destructive.ps1). Die Stufe verweigert den Lauf ohne
       Adminrechte, ohne erkannte VM, ohne Bestätigung oder wenn EDEP schon angewendet ist. Nach dem Lauf ordentlich neu starten.

    Exit-Code: 0 = alle automatisch geprüften L1-Anforderungen erfüllt und Integrität bestätigt;
    1 = mindestens eine Abweichung; 2 = Ergebnis unvollständig (UNKNOWN, Integrität nicht prüfbar oder nur Zeilenenden abweichend).

.PARAMETER Probe
    Misst zusätzlich die Update-Erreichbarkeit (Netz nötig, ändert nichts) und führt die Einheitentests aus.

.PARAMETER Destructive
    Führt zusätzlich die Stufe "Destructive" aus (siehe oben). Braucht -ConfirmDestructive. Die Ausgabe dieser Stufe ist nur deutsch.

.PARAMETER ConfirmDestructive
    Ausdrückliche Bestätigung, dass das System verändert werden darf (Test-VM mit Prüfpunkt).

.PARAMETER SkipIntegrity
    Überspringt die Prüfung von SHA256SUMS und Signatur (zum Beispiel in einem Arbeitsstand mit eigenen Änderungen).

.PARAMETER OutputPath
    Ordner für das Protokoll. Standard: aktuelles Verzeichnis.

.PARAMETER Language
    de oder en für die Konsolenausgabe und die Detailtexte. Standard: Windows-Anzeigesprache.

.PARAMETER PassThru
    Gibt das Protokollobjekt zusätzlich zurück.

.EXAMPLE
    .\conformance\Test-EdepConformance.ps1
.EXAMPLE
    .\conformance\Test-EdepConformance.ps1 -Probe -OutputPath C:\temp
#>
[CmdletBinding()]
param(
    [switch]$Probe,
    [switch]$SkipIntegrity,
    [switch]$Destructive,
    [switch]$ConfirmDestructive,
    [string]$OutputPath = (Get-Location).ProviderPath,
    [ValidateSet('de', 'en')][string]$Language,
    [switch]$PassThru
)

$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$l1 = Join-Path $root 'baseline\L1'
. (Join-Path $l1 'EdepStrings.ps1')
. (Join-Path $l1 'EdepL1.Common.ps1')
. (Join-Path $l1 'EdepL1.Checks.ps1')
. (Join-Path $PSScriptRoot 'EdepConformance.Common.ps1')
. (Join-Path $PSScriptRoot 'EdepConformance.Destructive.ps1')
if ($Language) { Set-EdepLanguage $Language }
$de = ($EdepLanguage -eq 'de')
function T([string]$German, [string]$English) { if ($de) { $German } else { $English } }

$isAdmin = Test-EdepIsAdmin
$os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
$cs = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
$cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction SilentlyContinue
$environment = [ordered]@{
    computer = $env:COMPUTERNAME
    os = $(if ($os) { "$($os.Caption) $($os.Version)" } else { $null })
    edition = $(if ($cv) { [string]$cv.EditionID } else { $null })
    displayVersion = $(if ($cv) { [string]$cv.DisplayVersion } else { $null })
    build = $(if ($cv) { "$($cv.CurrentBuildNumber).$($cv.UBR)" } else { $null })
    powershell = $PSVersionTable.PSVersion.ToString()
    isAdmin = $isAdmin
    isVirtualMachine = $(if ($cs) { ($cs.Model -match 'Virtual|VMware|KVM|HVM') } else { $null })
}
Write-Host (T "EDEP-Konformitätsprüfung (Version $EdepVersion) auf $($env:COMPUTERNAME)" "EDEP conformance check (version $EdepVersion) on $($env:COMPUTERNAME)") -ForegroundColor White
if (-not $isAdmin) { Write-Host (T 'Ohne Adminrechte: einige Prüfungen sind "UNKNOWN".' 'Without admin rights: some checks are "UNKNOWN".') -ForegroundColor Yellow }

# 1. Integrität
$sumsPath = Join-Path $root 'SHA256SUMS'
$integrity = [ordered]@{ checksums = [ordered]@{ status = 'SKIPPED'; detail = $null }; signature = [ordered]@{ status = 'SKIPPED'; detail = $null; fingerprint = $null } }
if ($SkipIntegrity) {
    $integrity.checksums.detail = (T 'übersprungen (-SkipIntegrity)' 'skipped (-SkipIntegrity)')
}
elseif (-not (Test-Path -LiteralPath $sumsPath)) {
    $integrity.checksums.detail = (T 'keine SHA256SUMS in diesem Stand (nur Releases ab 0.1.0-draft.3)' 'no SHA256SUMS in this tree (releases from 0.1.0-draft.3 only)')
}
else {
    $entries = @(ConvertFrom-EdepSums (Get-Content -LiteralPath $sumsPath -Encoding UTF8))
    $r = Test-EdepSumsAgainstFiles -Entries $entries -Root $root
    $integrity.checksums = [ordered]@{
        status = (Get-EdepIntegrityStatus $r); total = $r.Total; ok = $r.Ok
        lineEndings = @($r.LineEndings); mismatch = @($r.Mismatch); missing = @($r.Missing); invalidLines = $r.Invalid
        detail = $(if ($r.LineEndings.Count -and -not ($r.Mismatch.Count -or $r.Missing.Count)) { (T 'nur Zeilenenden weichen ab (Klon statt ZIP-Stand?), Prüfung mit dem ZIP des Tags wiederholen' 'only line endings differ (clone instead of ZIP?), repeat with the tag ZIP') } else { $null })
    }
    $s = Test-EdepSumsSignature -Root $root
    $integrity.signature = [ordered]@{ status = $s.Status; detail = $s.Detail; fingerprint = $s.Fingerprint }
}
Write-Host ('{0,-7} {1}' -f $integrity.checksums.status, (T 'Prüfsummen' 'Checksums')) -ForegroundColor $(if ($integrity.checksums.status -eq 'PASS') { 'Green' } elseif ($integrity.checksums.status -eq 'FAIL') { 'Red' } else { 'Yellow' })
Write-Host ('{0,-7} {1}' -f $integrity.signature.status, (T 'Signatur' 'Signature')) -ForegroundColor $(if ($integrity.signature.status -eq 'PASS') { 'Green' } elseif ($integrity.signature.status -eq 'FAIL') { 'Red' } else { 'Yellow' })

# 2. L1-Prüfungen
$l1Raw = @(Get-EdepL1CheckResult -ProbeUpdates:$Probe)
$l1Results = @($l1Raw | ForEach-Object {
    [ordered]@{ requirement = $_.Id; test = ($_.Id -replace '^EDEP-', 'T-'); art = 'auto'; status = $_.Status; detail = $_.Detail }
})
foreach ($r in $l1Raw) {
    $color = switch ($r.Status) { 'PASS' { 'Green' } 'WARN' { 'Yellow' } default { 'Red' } }
    Write-Host ('{0,-7} {1,-12} {2}' -f $r.Status, $r.Id, $r.Detail) -ForegroundColor $color
}
$failed = @($l1Raw | Where-Object { $_.Status -in 'FAIL', 'UNKNOWN' }).Count

# 3. Audit
$audit = $null
try {
    Import-Module (Join-Path $l1 'EDEP.psd1') -Force
    $a = Invoke-EdepAudit -NoHtml -PassThru 6>$null 3>$null
    $audit = [ordered]@{ score = $a.Score.Score; grade = $a.Score.Grade; counts = $a.Counts }
}
catch { $audit = [ordered]@{ error = $_.Exception.Message } }

# 4. Einheitentests (nur mit -Probe)
$unit = [ordered]@{ ran = $false }
if ($Probe) {
    $unitScript = Join-Path $root 'tools\Test-EdepUnits.ps1'
    if (Test-Path -LiteralPath $unitScript) {
        $lines = @(& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $unitScript 2>&1 | ForEach-Object { [string]$_ })
        $unit = [ordered]@{ ran = $true; exitCode = $LASTEXITCODE
            passed = @($lines | Where-Object { $_ -match '^PASS ' }).Count; failed = @($lines | Where-Object { $_ -match '^FAIL ' }).Count }
        Write-Host ('{0,-7} {1}' -f $(if ($unit.exitCode -eq 0) { 'PASS' } else { 'FAIL' }), (T "Einheitentests: $($unit.passed) bestanden, $($unit.failed) fehlgeschlagen" "Unit tests: $($unit.passed) passed, $($unit.failed) failed")) -ForegroundColor $(if ($unit.exitCode -eq 0) { 'Green' } else { 'Red' })
    }
    else { $unit = [ordered]@{ ran = $false; detail = 'tools\Test-EdepUnits.ps1 nicht gefunden' } }
}

# 4b. Destructive (nur mit -Destructive; ändert das System)
$destructiveResult = $null
if ($Destructive) {
    $profilesNow = @(Get-NetFirewallProfile -PolicyStore ActiveStore | ForEach-Object { [string]$_.DefaultOutboundAction })
    $edepRules = @(Get-NetFirewallRule -Group $EdepRuleGroup -ErrorAction SilentlyContinue).Count
    $refused = @(Test-EdepDestructiveGuard -IsVirtualMachine ([bool]$environment.isVirtualMachine) -IsAdmin $isAdmin -Confirmed ([bool]$ConfirmDestructive) -EdepRuleCount $edepRules -OutboundActions $profilesNow)
    if ($refused.Count) {
        Write-Host (T 'Destructive abgelehnt:' 'Destructive refused:') -ForegroundColor Red
        $refused | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
        $destructiveResult = [ordered]@{ ran = $false; refused = $refused }
    }
    else {
        Write-Host (T 'Destructive: das System wird verändert und am Ende zurückgenommen ...' 'Destructive: the system will be changed and rolled back ...') -ForegroundColor Yellow
        $destructiveResult = Invoke-EdepDestructiveRun -L1 $l1 -FingerprintScript (Join-Path $PSScriptRoot 'Get-EdepFingerprint.ps1') -WorkDir $OutputPath
        foreach ($st in $destructiveResult.steps) {
            $color = switch ($st.status) { 'PASS' { 'Green' } 'FAIL' { 'Red' } default { 'Yellow' } }
            Write-Host ('{0,-14} {1,-6} {2}  [{3}]' -f $st.status, $st.id, $st.name, $st.observed) -ForegroundColor $color
        }
        foreach ($e in $destructiveResult.errors) { Write-Host "FEHLER $e" -ForegroundColor Red }
        Write-Host (T 'Bitte jetzt ordentlich neu starten und Test-EdepL1 ausführen (SPEC 3.6).' 'Please restart normally now and run Test-EdepL1 (SPEC 3.6).') -ForegroundColor Yellow
    }
}

# 5. Nicht ausgeführt
$executedTests = @(); if ($destructiveResult -and $destructiveResult.ran) { $executedTests = @($destructiveResult.steps | Where-Object { $_.status -in 'PASS', 'FAIL' } | ForEach-Object { $_.tests } | Select-Object -Unique) }
$notRun = @(Get-EdepManualTest -ReadmePath (Join-Path $PSScriptRoot 'README.md') | Where-Object { $executedTests -notcontains $_.Test } | ForEach-Object {
    [ordered]@{ test = $_.Test; requirement = $_.Requirement; art = $_.Art
                reason = $(if ($_.Art -eq 'aktiv') { 'Angriffssimulation nur in einer Test-VM (siehe docs/TESTPLAN-L1.md)' } else { 'Prüfung von Code oder Dokumentation (Review)' }) } })

$exitCode = Get-EdepConformanceExitCode -L1Results $l1Raw -IntegrityStatus $integrity.checksums.status -SignatureStatus $integrity.signature.status
if ($destructiveResult -and $destructiveResult.ran -and $destructiveResult.failed -gt 0) { $exitCode = 1 }
if ($destructiveResult -and -not $destructiveResult.ran -and $exitCode -eq 0) { $exitCode = 2 }
$verdictText = switch ($exitCode) {
    0 { T 'Alle automatisch geprüften L1-Anforderungen erfüllt, Integrität bestätigt. Kein Konformitätsnachweis: die Tests unter "notRun" liefen nicht.' 'All automatically checked L1 requirements met, integrity confirmed. Not a conformance proof: the tests under "notRun" did not run.' }
    1 { T 'Abweichungen gefunden (FAIL).' 'Deviations found (FAIL).' }
    default { T 'Ergebnis unvollständig (UNKNOWN, Integrität nicht prüfbar oder nur Zeilenenden abweichend).' 'Result incomplete (UNKNOWN, integrity not verifiable or only line endings differ).' }
}

$report = [ordered]@{
    profile = 'EDEP-Conformance'; schemaVersion = 1; edepVersion = $EdepVersion
    generated = (Get-Date).ToString('o'); mode = [ordered]@{ probe = [bool]$Probe; skipIntegrity = [bool]$SkipIntegrity }
    environment = $environment; integrity = $integrity
    l1 = [ordered]@{ total = $l1Raw.Count; passed = ($l1Raw.Count - $failed); conform = ($failed -eq 0); results = $l1Results }
    unitTests = $unit; audit = $audit; destructive = $destructiveResult; notRun = $notRun
    verdict = [ordered]@{ exitCode = $exitCode; text = $verdictText }
    note = 'Dieses Protokoll hält fest, was gemessen wurde. Es ist kein Konformitätsnachweis. Siehe SPEC.md Abschnitt 5 und docs/EVIDENCE.md.'
}
$file = Join-Path $OutputPath ('edep-conformance-{0}-{1}.json' -f $env:COMPUTERNAME, (Get-Date -Format 'yyyyMMdd-HHmmss'))
$report | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $file -Encoding UTF8
Write-Host ''
Write-Host $verdictText -ForegroundColor $(if ($exitCode -eq 0) { 'Green' } elseif ($exitCode -eq 1) { 'Red' } else { 'Yellow' })
Write-Host (T "Protokoll: $file" "Report: $file")
if ($PassThru) { [pscustomobject]$report }
exit $exitCode
