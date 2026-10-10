# Stufe "Destructive" von Test-EdepConformance.ps1: ÄNDERT DAS SYSTEM. Nur in einer Test-VM.
# Ablauf nach docs/TESTPLAN-L1.md (Phasen A bis D, Rücknahme): Fingerabdruck, Install (Audit), Install (Enforce),
# Umgehungstests, Restore, Fingerabdruck-Vergleich. Alles, was angelegt wird, wird entfernt; ein Abbruch löst Restore aus.
# Die reinen Auswertungsfunktionen (Guard, Fingerabdruck-Vergleich, Statusabgleich) prüft tools/Test-EdepUnits.ps1.

function Test-EdepDestructiveGuard {
    # Liefert die Gründe, aus denen die Stufe NICHT laufen darf (leer = darf laufen).
    param([bool]$IsVirtualMachine, [bool]$IsAdmin, [bool]$Confirmed, [int]$EdepRuleCount, [string[]]$OutboundActions = @())
    $reasons = @()
    if (-not $IsAdmin) { $reasons += 'Adminrechte fehlen' }
    if (-not $IsVirtualMachine) { $reasons += 'keine virtuelle Maschine erkannt (die Stufe läuft nur in einer Test-VM)' }
    if (-not $Confirmed) { $reasons += '-ConfirmDestructive fehlt (ausdrückliche Bestätigung nötig)' }
    if ($EdepRuleCount -gt 0) { $reasons += 'EDEP ist bereits angewendet (Regeln der Gruppe EDEP-L1 vorhanden); zuerst Restore-EdepL1.ps1 ausführen' }
    if ($OutboundActions -contains 'Block') { $reasons += 'ausgehend steht bereits auf Block; der Ausgangszustand ist nicht sauber' }
    $reasons
}

function Test-EdepFingerprintIdentical {
    # Vergleicht zwei Fingerabdruck-Dateien (Zeilen) ohne Zeitstempel.
    param([string[]]$A, [string[]]$B)
    $x = @($A | Where-Object { $_ -notmatch 'erzeugt' })
    $y = @($B | Where-Object { $_ -notmatch 'erzeugt' })
    if ($x.Count -eq 0 -and $y.Count -eq 0) { return $false }
    @(Compare-Object $x $y).Count -eq 0
}

function Get-EdepOwnFirstBackup {
    # Name der ersten Sicherung, die ein Lauf neu angelegt hat (Namen sind Zeitstempel, die älteste neue gewinnt).
    # $null, wenn keine neue Sicherung entstanden ist.
    param([string[]]$Before = @(), [string[]]$After = @())
    $new = @($After | Where-Object { $_ -and ($Before -notcontains $_) } | Sort-Object)
    if ($new.Count -eq 0) { return $null }
    $new[0]
}

function Test-EdepRestoreNeeded {
    # Die Rücknahme ist nötig, sobald der Install angewendet wurde oder auch nur eine eigene Sicherung angelegt hat
    # (ein Install kann nach der Sicherung abbrechen, dann ist das System teilweise geändert).
    param([bool]$Applied, [string]$OwnBackup)
    $Applied -or -not [string]::IsNullOrEmpty($OwnBackup)
}

function Test-EdepAppControlTemplate {
    # Ohne die Beispielvorlage lässt sich -DeployAppControlAudit nicht ausführen (zum Beispiel Windows 11 Home).
    Test-Path -LiteralPath $EdepAppControlTemplate
}

function Get-EdepExpectedAuditFailures {
    # Erwartete nicht erfüllte Prüfungen im Audit-Modus (sortiert wie Get-EdepFailedIds).
    param([bool]$AppControl)
    if ($AppControl) { @('EDEP-NET-03') } else { @('EDEP-ID-01', 'EDEP-NET-03') }
}

function Get-EdepExpectedEnforceFailures {
    # Erwartete nicht erfüllte Prüfungen unter Enforce.
    param([bool]$AppControl)
    if ($AppControl) { @() } else { @('EDEP-ID-01') }
}

function Get-EdepFailedIds {
    # IDs der Prüfungen mit FAIL oder UNKNOWN (sortiert).
    param($Results)
    @($Results | Where-Object { $_.Status -in 'FAIL', 'UNKNOWN' } | ForEach-Object { [string]$_.Id } | Sort-Object)
}

function Get-EdepStatusOf {
    param($Results, [string]$Id)
    $r = @($Results | Where-Object { $_.Id -eq $Id }) | Select-Object -First 1
    if ($r) { [string]$r.Status } else { 'FEHLT' }
}

function New-EdepStep {
    # Status: PASS (Erwartung eingetreten), FAIL (Abweichung), NOT_ASSESSABLE (nicht prüfbar, zählt nicht), INFO.
    param([string]$Id, [string[]]$Tests, [string]$Name, [string]$Expected, [string]$Observed, [string]$Status)
    [ordered]@{ id = $Id; tests = @($Tests); name = $Name; expected = $Expected; observed = $Observed; status = $Status }
}

function Get-EdepCurlCode {
    param([string]$Exe, [string]$Url = 'https://example.org')
    try { [string](& $Exe -m 10 -s -o NUL -w '%{http_code}' $Url) } catch { 'Fehler' }
}

function Test-EdepBitsTransfer {
    param([string]$Url = 'https://example.org', [int]$TimeoutSec = 60)
    $j = Start-Job -ArgumentList $Url -ScriptBlock {
        param($u)
        try { Start-BitsTransfer -Source $u -Destination (Join-Path $env:TEMP ('edep-bt-' + [guid]::NewGuid().ToString('N') + '.tmp')) -ErrorAction Stop; 'ERFOLG' }
        catch { 'FEHLER' }
    }
    if (Wait-Job $j -Timeout $TimeoutSec) { $r = Receive-Job $j } else { $r = 'HÄNGT'; Stop-Job $j }
    Remove-Job $j -Force -ErrorAction SilentlyContinue
    Remove-Item (Join-Path $env:TEMP 'edep-bt-*.tmp') -Force -ErrorAction SilentlyContinue
    [string]$r
}

function Invoke-EdepDestructiveRun {
    param([string]$L1, [string]$FingerprintScript, [string]$WorkDir)
    $errors = @(); $applied = $false; $restored = $false
    $stepList = New-Object System.Collections.ArrayList
    # Restore ohne -BackupPath nimmt die ÄLTESTE Sicherung (Zustand vor der ersten Installation überhaupt). Liegen
    # Sicherungen früherer Läufe vor, ginge die Rücknahme auf deren Stand zurück, nicht auf den vor diesem Lauf.
    # Deshalb übergibt die Stufe ihre eigene erste Sicherung (E-76-Messung auf Pro, 2026-10-10).
    $backupNames = { @(Get-ChildItem -Path $EdepBackupRoot -Directory -ErrorAction SilentlyContinue | Where-Object { Test-Path (Join-Path $_.FullName 'manifest.json') } | ForEach-Object { $_.Name }) }
    $backupsBefore = & $backupNames
    $olderBackups = @($backupsBefore).Count
    $ownBackup = $null; $restoreMode = 'älteste Sicherung (Standard)'
    $appControl = [bool](Test-EdepAppControlTemplate)
    $install = Join-Path $L1 'Install-EdepL1.ps1'; $restore = Join-Path $L1 'Restore-EdepL1.ps1'
    $edge = "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe"
    $x = Join-Path $env:TEMP 'edep-x.exe'; $bad = Join-Path $env:LOCALAPPDATA 'edep-test.exe'
    $fpBefore = Join-Path $WorkDir 'destructive-vorher.json'; $fpAfter = Join-Path $WorkDir 'destructive-nachher.json'
    $curl = Join-Path $env:SystemRoot 'System32\curl.exe'
    function Add-Step($s) { [void]$stepList.Add($s) }
    try {
        # Phase A: Ausgangszustand
        & $FingerprintScript -Root $L1 -Out $fpBefore | Out-Null
        Copy-Item $curl $x -Force
        $netCurl = Get-EdepCurlCode $curl; $netX = Get-EdepCurlCode $x
        $netOk = ($netCurl -eq '200' -and $netX -eq '200')
        Add-Step (New-EdepStep 'D-A1' @('T-NET-03a') 'Ausgangszustand: Netz und unbekanntes Programm erreichen das Ziel' '200 und 200' ("curl.exe $netCurl, x.exe $netX") $(if ($netOk) { 'PASS' } else { 'NOT_ASSESSABLE' }))

        # Phase B: Audit-Modus
        $pB = @{ Confirm = $false }
        if ($appControl) { $pB.DeployAppControlAudit = $true }
        $null = & $install @pB *>&1 | Out-String
        $applied = $true
        $ownBackup = Get-EdepOwnFirstBackup -Before $backupsBefore -After (& $backupNames)
        $b = @(Get-EdepL1CheckResult)
        $failedB = Get-EdepFailedIds $b
        $expB = @(Get-EdepExpectedAuditFailures -AppControl $appControl)
        $nameB = if ($appControl) { 'Audit-Modus: nur EDEP-NET-03 ist nicht erfüllt' } else { 'Audit-Modus ohne App Control (Vorlage fehlt): nur EDEP-ID-01 und EDEP-NET-03 sind nicht erfüllt' }
        Add-Step (New-EdepStep 'D-B1' @('T-OPS-02', 'T-NET-03') $nameB ('FAIL nur bei ' + ($expB -join ' und ')) ('nicht erfüllt: ' + ($failedB -join ', ')) $(if ((@($failedB) -join ',') -eq ($expB -join ',')) { 'PASS' } else { 'FAIL' }))
        if ($netOk) {
            $cB = Get-EdepCurlCode $curl; $xB = Get-EdepCurlCode $x
            Add-Step (New-EdepStep 'D-B2' @('T-NET-04a') 'Audit-Modus: curl.exe ist blockiert (LOLBin-Regel)' '000' $cB $(if ($cB -eq '000') { 'PASS' } else { 'FAIL' }))
            Add-Step (New-EdepStep 'D-B3' @('T-BYP-07') 'Audit-Modus: umbenannte Kopie von curl.exe kommt durch (B-07)' '200' $xB $(if ($xB -eq '200') { 'PASS' } else { 'FAIL' }))
        }

        # Phase C: Enforce
        $p = @{ Enforce = $true; AllowWindowsUpdate = $true; Confirm = $false }
        if ($appControl) { $p.DeployAppControlAudit = $true }
        if (Test-Path -LiteralPath $edge) { $p.AllowProgram = $edge }
        $null = & $install @p *>&1 | Out-String
        $c = @(Get-EdepL1CheckResult)
        $failedC = Get-EdepFailedIds $c
        $expC = @(Get-EdepExpectedEnforceFailures -AppControl $appControl)
        $nameC = if ($appControl) { 'Enforce mit -AllowWindowsUpdate: alle 15 Prüfungen erfüllt (TEL-02 und TEL-04 dürfen WARN sein)' } else { 'Enforce mit -AllowWindowsUpdate ohne App Control (Vorlage fehlt): nur EDEP-ID-01 nicht erfüllt (TEL-02 und TEL-04 dürfen WARN sein)' }
        $expTextC = if ($appControl) { 'keine Prüfung FAIL oder UNKNOWN' } else { 'nur EDEP-ID-01 FAIL' }
        Add-Step (New-EdepStep 'D-C1' @('T-NET-03') $nameC $expTextC $(if ($failedC.Count) { 'nicht erfüllt: ' + ($failedC -join ', ') } else { 'alle erfüllt' }) $(if ((@($failedC) -join ',') -eq ($expC -join ',')) { 'PASS' } else { 'FAIL' }))
        if ($netOk) {
            $cC = Get-EdepCurlCode $curl; $xC = Get-EdepCurlCode $x
            Add-Step (New-EdepStep 'D-C2' @('T-NET-04a', 'T-NET-03a') 'Enforce: curl.exe ist blockiert' '000' $cC $(if ($cC -eq '000') { 'PASS' } else { 'FAIL' }))
            Add-Step (New-EdepStep 'D-C3' @('T-BYP-07', 'T-NET-03a') 'Enforce: umbenannte Kopie von curl.exe ist blockiert' '000' $xC $(if ($xC -eq '000') { 'PASS' } else { 'FAIL' }))
            $bits = Test-EdepBitsTransfer
            Add-Step (New-EdepStep 'D-C4' @('T-BYP-01') 'Enforce: BITS zu example.org gelingt nicht (B-01, gemessen: blockiert)' 'FEHLER oder HÄNGT' $bits $(if ($bits -ne 'ERFOLG') { 'PASS' } else { 'FAIL' }))
        }

        # Phase D: Umgehungen (Install prüft zuerst, ob die Datei existiert; deshalb vorher eine Kopie im Benutzerprofil anlegen)
        Copy-Item $curl $bad -Force
        try {
            $null = & $install -AllowProgram $bad -WhatIf *>&1 | Out-String
            Add-Step (New-EdepStep 'D-D1' @('T-NET-10a', 'T-BYP-04') '-AllowProgram mit beschreibbarem Pfad bricht ab (EDEP-NET-10)' 'Abbruch mit Verweis auf EDEP-NET-10' 'kein Abbruch' 'FAIL')
        }
        catch { Add-Step (New-EdepStep 'D-D1' @('T-NET-10a', 'T-BYP-04') '-AllowProgram mit beschreibbarem Pfad bricht ab (EDEP-NET-10)' 'Abbruch mit Verweis auf EDEP-NET-10' ('Abbruch: ' + (($_.Exception.Message -split "`n")[0])) $(if ($_.Exception.Message -match 'EDEP-NET-10') { 'PASS' } elseif ($_.Exception.Message -match 'nicht gefunden') { 'NOT_ASSESSABLE' } else { 'FAIL' })) }

        try {
            New-NetFirewallRule -DisplayName 'EDEP-Test-B05' -Direction Outbound -Action Allow -Program $curl -Authentication Required -OverrideBlockRules $true -ErrorAction Stop | Out-Null
            $d5 = Get-EdepStatusOf @(Get-EdepL1CheckResult) 'EDEP-NET-04'
            Add-Step (New-EdepStep 'D-D2' @('T-NET-04b', 'T-BYP-05') 'Authenticated-Bypass-Regel anlegen: EDEP-NET-04 meldet FAIL (B-05)' 'FAIL' $d5 $(if ($d5 -eq 'FAIL') { 'PASS' } else { 'FAIL' }))
        }
        catch { Add-Step (New-EdepStep 'D-D2' @('T-NET-04b', 'T-BYP-05') 'Authenticated-Bypass-Regel anlegen: EDEP-NET-04 meldet FAIL (B-05)' 'FAIL' ('Regel nicht herstellbar: ' + $_.Exception.Message) 'NOT_ASSESSABLE') }
        Remove-NetFirewallRule -DisplayName 'EDEP-Test-B05' -ErrorAction SilentlyContinue

        try {
            New-NetFirewallRule -DisplayName 'EDEP-Test-offen' -Direction Outbound -Action Allow -Profile Any -ErrorAction Stop | Out-Null
            $d6 = Get-EdepStatusOf @(Get-EdepL1CheckResult) 'EDEP-NET-03'
            Add-Step (New-EdepStep 'D-D3' @('T-NET-03b', 'T-BYP-08') 'Uneingeschränkte ausgehende Erlaubnisregel: EDEP-NET-03 meldet FAIL (B-08)' 'FAIL' $d6 $(if ($d6 -eq 'FAIL') { 'PASS' } else { 'FAIL' }))
        }
        catch { Add-Step (New-EdepStep 'D-D3' @('T-NET-03b', 'T-BYP-08') 'Uneingeschränkte ausgehende Erlaubnisregel: EDEP-NET-03 meldet FAIL (B-08)' 'FAIL' ('Regel nicht herstellbar: ' + $_.Exception.Message) 'NOT_ASSESSABLE') }
        Remove-NetFirewallRule -DisplayName 'EDEP-Test-offen' -ErrorAction SilentlyContinue
        $left = @(Get-NetFirewallRule -DisplayName 'EDEP-Test-B05', 'EDEP-Test-offen' -ErrorAction SilentlyContinue).Count
        Add-Step (New-EdepStep 'D-D4' @() 'Testregeln wieder entfernt' '0 Reste' ("$left Reste") $(if ($left -eq 0) { 'PASS' } else { 'FAIL' }))
    }
    catch { $errors += $_.Exception.Message }
    finally {
        if (-not $ownBackup) { $ownBackup = Get-EdepOwnFirstBackup -Before $backupsBefore -After (& $backupNames) }
        if (Test-EdepRestoreNeeded -Applied $applied -OwnBackup $ownBackup) {
            try {
                if ($ownBackup) {
                    $restoreMode = "eigene Sicherung $ownBackup"
                    $null = & $restore -BackupPath (Join-Path $EdepBackupRoot $ownBackup) -Confirm:$false *>&1 | Out-String
                }
                else { $null = & $restore -Confirm:$false *>&1 | Out-String }
                $restored = $true
            }
            catch { $errors += ('Restore fehlgeschlagen: ' + $_.Exception.Message) }
        }
        Remove-NetFirewallRule -DisplayName 'EDEP-Test-B05', 'EDEP-Test-offen' -ErrorAction SilentlyContinue
        Remove-Item $x, $bad -Force -ErrorAction SilentlyContinue
    }
    $steps = @($stepList.ToArray())
    # Phase E: Rücknahme prüfen
    $identical = $false
    if ($restored) {
        try {
            & $FingerprintScript -Root $L1 -Out $fpAfter | Out-Null
            $identical = Test-EdepFingerprintIdentical (Get-Content $fpBefore) (Get-Content $fpAfter)
        }
        catch { $errors += ('Fingerabdruck nach der Rücknahme: ' + $_.Exception.Message) }
        $steps += ,(New-EdepStep 'D-E1' @('T-OPS-01a') 'Rücknahme: Fingerabdruck identisch zum Ausgangszustand' 'identisch' $(if ($identical) { 'identisch' } else { 'weicht ab' }) $(if ($identical) { 'PASS' } else { 'FAIL' }))
    }
    else { $steps += ,(New-EdepStep 'D-E1' @('T-OPS-01a') 'Rücknahme: Fingerabdruck identisch zum Ausgangszustand' 'identisch' 'Rücknahme nicht ausgeführt' 'FAIL') }
    $failed = @($steps | Where-Object { $_.status -eq 'FAIL' }).Count + $errors.Count
    [ordered]@{
        ran = $true; failed = $failed; passed = @($steps | Where-Object { $_.status -eq 'PASS' }).Count
        notAssessable = @($steps | Where-Object { $_.status -eq 'NOT_ASSESSABLE' }).Count
        restored = $restored; fingerprintIdentical = $identical; errors = @($errors); steps = @($steps)
        olderBackups = $olderBackups; restoreMode = $restoreMode; appControlAvailable = $appControl
        note = 'Nach der Rücknahme ordentlich neu starten und Test-EdepL1 ausführen (SPEC 3.6, E-76).'
    }
}
