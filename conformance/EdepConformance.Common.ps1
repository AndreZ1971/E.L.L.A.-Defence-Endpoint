# Hilfsfunktionen für Test-EdepConformance.ps1 (Prüfsummen, Signatur, Auswertung). Ändern nichts am System.
# Werden von den Einheitentests (tools/Test-EdepUnits.ps1) ohne Adminrechte geprüft.

function ConvertFrom-EdepSums {
    # Zeilenformat von sha256sum: "<64 Hex-Zeichen>  <Pfad>" (zwei Leerzeichen). Andere Zeilen gelten als ungültig.
    param([string[]]$Lines)
    foreach ($l in $Lines) {
        if ([string]::IsNullOrWhiteSpace($l)) { continue }
        if ($l -match '^([0-9a-fA-F]{64})  (.+)$') {
            [pscustomobject]@{ Hash = $Matches[1].ToLowerInvariant(); Path = $Matches[2]; Valid = $true }
        }
        else { [pscustomobject]@{ Hash = $null; Path = $l; Valid = $false } }
    }
}

function Get-EdepSha256Hex([byte[]]$Bytes) {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { ([BitConverter]::ToString($sha.ComputeHash($Bytes)) -replace '-', '').ToLowerInvariant() }
    finally { $sha.Dispose() }
}

function Get-EdepLineEndingVariantHash([byte[]]$Bytes) {
    # Hashes derselben Datei mit nur LF und mit nur CRLF (Klon unter Windows wandelt Zeilenenden um, siehe docs/SIGNING.md).
    $enc = [Text.Encoding]::GetEncoding(28591)
    $lf = $enc.GetString($Bytes).Replace("`r`n", "`n")
    @{ Lf = (Get-EdepSha256Hex $enc.GetBytes($lf)); Crlf = (Get-EdepSha256Hex $enc.GetBytes($lf.Replace("`n", "`r`n"))) }
}

function Test-EdepSumsAgainstFiles {
    param($Entries, [string]$Root)
    $ok = 0; $lineEndings = @(); $mismatch = @(); $missing = @()
    $valid = @($Entries | Where-Object { $_.Valid })
    foreach ($e in $valid) {
        $p = Join-Path $Root ($e.Path -replace '/', '\')
        if (-not (Test-Path -LiteralPath $p -PathType Leaf)) { $missing += $e.Path; continue }
        $bytes = [IO.File]::ReadAllBytes($p)
        if ((Get-EdepSha256Hex $bytes) -eq $e.Hash) { $ok++; continue }
        $v = Get-EdepLineEndingVariantHash $bytes
        if ($v.Lf -eq $e.Hash -or $v.Crlf -eq $e.Hash) { $lineEndings += $e.Path } else { $mismatch += $e.Path }
    }
    [pscustomobject]@{
        Total = $valid.Count; Ok = $ok; LineEndings = $lineEndings; Mismatch = $mismatch; Missing = $missing
        Invalid = @($Entries | Where-Object { -not $_.Valid }).Count
    }
}

function Get-EdepIntegrityStatus($Result) {
    # PASS: alles stimmt. WARN: nur Zeilenenden weichen ab (Klon statt ZIP-Stand). FAIL: Inhalt weicht ab oder Datei fehlt.
    if (-not $Result -or $Result.Total -eq 0) { return 'FAIL' }
    if ($Result.Mismatch.Count -or $Result.Missing.Count -or $Result.Invalid) { return 'FAIL' }
    if ($Result.LineEndings.Count) { return 'WARN' }
    'PASS'
}

function Test-EdepSumsSignature {
    param([string]$Root)
    $sums = Join-Path $Root 'SHA256SUMS'; $sig = Join-Path $Root 'SHA256SUMS.sig'; $allowed = Join-Path $Root 'allowed_signers'
    if (-not (Test-Path -LiteralPath $sums) -or -not (Test-Path -LiteralPath $sig) -or -not (Test-Path -LiteralPath $allowed)) {
        return [pscustomobject]@{ Status = 'SKIPPED'; Detail = 'keine Signatur im Stand (SHA256SUMS.sig oder allowed_signers fehlt)'; Fingerprint = $null }
    }
    $ssh = Get-Command ssh-keygen.exe -ErrorAction SilentlyContinue
    if (-not $ssh) { return [pscustomobject]@{ Status = 'SKIPPED'; Detail = 'ssh-keygen nicht gefunden'; Fingerprint = $null } }
    $out = Join-Path ([IO.Path]::GetTempPath()) "edep-sigverify-$PID.txt"
    $argList = '-Y verify -f "{0}" -I edep-release -n edep-release -s "{1}"' -f $allowed, $sig
    $p = Start-Process -FilePath $ssh.Source -ArgumentList $argList -RedirectStandardInput $sums -RedirectStandardOutput $out `
        -RedirectStandardError "$out.err" -Wait -PassThru -NoNewWindow
    $text = ''
    if (Test-Path $out) { $text += (Get-Content $out -Raw) }
    if (Test-Path "$out.err") { $text += (Get-Content "$out.err" -Raw) }
    Remove-Item $out, "$out.err" -Force -ErrorAction SilentlyContinue
    if ($p.ExitCode -eq 0 -and $text -match 'Good "edep-release" signature.*?(SHA256:[A-Za-z0-9+/=]+)') {
        [pscustomobject]@{ Status = 'PASS'; Detail = 'Signatur gültig'; Fingerprint = $Matches[1] }
    }
    else { [pscustomobject]@{ Status = 'FAIL'; Detail = ($text.Trim() -replace '\s+', ' '); Fingerprint = $null } }
}

function Get-EdepConformanceExitCode {
    # 0: alle automatisch geprüften L1-Anforderungen erfüllt und Integrität bestätigt.
    # 1: mindestens eine Abweichung (FAIL).
    # 2: Ergebnis unvollständig (UNKNOWN, Integrität nicht prüfbar oder nur Zeilenenden abweichend).
    param($L1Results, [string]$IntegrityStatus, [string]$SignatureStatus)
    $l1 = @($L1Results)
    if (@($l1 | Where-Object { $_.Status -eq 'FAIL' }).Count -or $IntegrityStatus -eq 'FAIL' -or $SignatureStatus -eq 'FAIL') { return 1 }
    if (@($l1 | Where-Object { $_.Status -eq 'UNKNOWN' }).Count -or $IntegrityStatus -ne 'PASS') { return 2 }
    0
}

function Get-EdepManualTest {
    # Tests der Stufe L1 aus conformance/README.md, die nicht automatisch laufen: Art "aktiv" oder "Review" im Abschnitt L1
    # und die Umgehungstests T-BYP-xx der Stufe L1.
    param([string]$ReadmePath)
    if (-not (Test-Path -LiteralPath $ReadmePath)) { return @() }
    $section = ''
    foreach ($line in (Get-Content -LiteralPath $ReadmePath -Encoding UTF8)) {
        if ($line -match '^##\s+L1\b') { $section = 'L1'; continue }
        if ($line -match '^##\s+Umgehungstests') { $section = 'BYP'; continue }
        if ($line -match '^##\s+') { $section = ''; continue }
        if ($section -eq 'L1' -and $line -match '^\|\s*(T-[A-Z]+-\d+[a-z]?)\s*\|\s*([^|]+?)\s*\|\s*(aktiv|Review)[^|]*\|') {
            [pscustomobject]@{ Test = $Matches[1]; Requirement = ($Matches[2] -split ',')[0].Trim(); Art = $Matches[3] }
        }
        elseif ($section -eq 'BYP' -and $line -match '^\|\s*(T-BYP-\d+)\s*\|\s*([^|]+?)\s*\|\s*L1\s*\|') {
            [pscustomobject]@{ Test = $Matches[1]; Requirement = $Matches[2]; Art = 'aktiv' }
        }
    }
}
