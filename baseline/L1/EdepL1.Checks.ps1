# Prüflogik für EDEP L1. Wird von Test-EdepL1.ps1 und Invoke-EdepAudit gemeinsam genutzt.
# Setzt EdepL1.Common.ps1 voraus. Ändert nichts am System.
#
# Status: PASS | WARN (erfüllt, mit Hinweis) | FAIL | UNKNOWN (ohne Adminrechte nicht prüfbar)

function Test-EdepIsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-EdepProfileMatch($Rule, [string]$ProfileName) {
    $p = [string]$Rule.Profile
    ($p -match 'Any') -or ($p -match $ProfileName)
}

function Get-EdepL1CheckResult {
    [CmdletBinding()]
    param()

    $results = [System.Collections.Generic.List[object]]::new()
    function Add-Result([string]$Id, [string]$Status, [string]$Detail) {
        $results.Add([pscustomobject]@{ Id = $Id; Status = $Status; Detail = $Detail })
    }

    $isAdmin = Test-EdepIsAdmin
    $profiles = Get-NetFirewallProfile -PolicyStore ActiveStore

    # --- EDEP-NET-01 -------------------------------------------------------
    $bad = $profiles | Where-Object { -not $_.Enabled -or [string]$_.DefaultInboundAction -ne 'Block' }
    if ($bad) { Add-Result 'EDEP-NET-01' 'FAIL' "Nicht aktiv oder eingehend nicht Block: $($bad.Name -join ', ')" }
    else { Add-Result 'EDEP-NET-01' 'PASS' 'Alle Profile aktiv, eingehend Block' }

    # --- EDEP-NET-02 -------------------------------------------------------
    $stealthRoots = @($FirewallPolicyProfileKeys | ForEach-Object { "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\$_" }) +
                    @($FirewallProfileKeys.Values | ForEach-Object { "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\$_" })
    $stealthOff = foreach ($root in $stealthRoots) {
        $v = Get-ItemProperty -Path $root -Name DisableStealthMode -ErrorAction SilentlyContinue
        if ($v -and $v.DisableStealthMode -ne 0) { $root }
    }
    if ($stealthOff) { Add-Result 'EDEP-NET-02' 'FAIL' "Stealth-Modus deaktiviert: $($stealthOff -join '; ')" }
    else { Add-Result 'EDEP-NET-02' 'PASS' 'Stealth-Modus aktiv (Standard)' }

    # --- EDEP-NET-03 -------------------------------------------------------
    $allowCount = (Get-NetFirewallRule -PolicyStore ActiveStore -Direction Outbound -Action Allow -Enabled True -ErrorAction SilentlyContinue | Measure-Object).Count
    $bad = $profiles | Where-Object { [string]$_.DefaultOutboundAction -ne 'Block' }
    if ($bad) { Add-Result 'EDEP-NET-03' 'FAIL' "Ausgehend standardmäßig erlaubt: $($bad.Name -join ', '). Jedes Programm darf ins Netz." }
    else { Add-Result 'EDEP-NET-03' 'PASS' "Ausgehend Block in allen Profilen; $allowCount aktive ausgehende Erlaubnisregeln" }

    # Ausgehende Blockregeln einmal einsammeln (Programm- und Dienstfilter).
    $outBlock = @(Get-NetFirewallRule -PolicyStore ActiveStore -Direction Outbound -Action Block -Enabled True -ErrorAction SilentlyContinue)
    $blockedPrograms = @($outBlock | Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue |
        ForEach-Object { ConvertTo-EdepComparablePath $_.Program })
    $blockedServices = @($outBlock | Get-NetFirewallServiceFilter -ErrorAction SilentlyContinue |
        ForEach-Object { ([string]$_.Service).ToLowerInvariant() })

    # --- EDEP-NET-04 -------------------------------------------------------
    $lolbins = @(Get-EdepLolbinPaths)
    $missing = $lolbins | Where-Object { $blockedPrograms -notcontains (ConvertTo-EdepComparablePath $_) }
    if ($missing) {
        $short = @($missing | ForEach-Object { Split-Path $_ -Leaf } | Sort-Object -Unique)
        $names = ($short | Select-Object -First 8) -join ', '
        if ($short.Count -gt 8) { $names += " und $($short.Count - 8) weitere" }
        Add-Result 'EDEP-NET-04' 'FAIL' "$(@($missing).Count) von $($lolbins.Count) ohne ausgehende Blockregel: $names"
    }
    else {
        # Blockregeln gelten nicht gegen "Authenticated Bypass" (SPEC Q-05, Umgehung B-05).
        $bypass = @(Get-NetFirewallRule -PolicyStore ActiveStore -Direction Outbound -Action Allow -Enabled True -ErrorAction SilentlyContinue |
            Where-Object { ($_ | Get-NetFirewallSecurityFilter -ErrorAction SilentlyContinue).OverrideBlockRules })
        if ($bypass.Count) { Add-Result 'EDEP-NET-04' 'FAIL' "Ausgehende Authenticated-Bypass-Regeln heben Blockaden auf: $(($bypass.DisplayName | Select-Object -First 5) -join ', ')" }
        else { Add-Result 'EDEP-NET-04' 'PASS' "$($lolbins.Count) LOLBins ausgehend blockiert, keine Authenticated-Bypass-Regel" }
    }

    # --- EDEP-NET-05 -------------------------------------------------------
    $inBlockPublic = @(Get-NetFirewallRule -PolicyStore ActiveStore -Direction Inbound -Action Block -Enabled True -ErrorAction SilentlyContinue |
        Where-Object { Test-EdepProfileMatch $_ 'Public' })
    $blockedPorts = @($inBlockPublic | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue |
        Where-Object { [string]$_.Protocol -in 'TCP', 'Any' } |
        ForEach-Object { $_.LocalPort } | ForEach-Object { [string]$_ })
    $missing = $EdepPublicInboundBlockPorts | Where-Object { ($blockedPorts -notcontains $_) -and ($blockedPorts -notcontains 'Any') }
    if ($missing) { Add-Result 'EDEP-NET-05' 'FAIL' "Public eingehend nicht explizit gesperrt: TCP $($missing -join ', ')" }
    else { Add-Result 'EDEP-NET-05' 'PASS' "Public eingehend gesperrt: TCP $($EdepPublicInboundBlockPorts -join ', ')" }

    # --- EDEP-NET-10 -------------------------------------------------------
    # Programme mit ausgehender Erlaubnisregel dürfen nur von Admins änderbar sein (Umgehung B-04).
    $allowPrograms = @(Get-NetFirewallRule -PolicyStore ActiveStore -Direction Outbound -Action Allow -Enabled True -ErrorAction SilentlyContinue |
        Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue |
        ForEach-Object { [string]$_.Program } |
        Where-Object { $_ -and $_ -notin 'Any', 'System' } |
        ForEach-Object { [Environment]::ExpandEnvironmentVariables($_) } |
        Sort-Object -Unique)
    $unsafe = [System.Collections.Generic.List[object]]::new()
    $unknown = [System.Collections.Generic.List[string]]::new()
    foreach ($prog in $allowPrograms) {
        if (-not (Test-Path -LiteralPath $prog)) { continue }
        $why = @(Get-EdepWritableByNonAdmin $prog)
        $real = @($why | Where-Object { $_ -notlike 'UNBEKANNT:*' })
        if ($real.Count) { $unsafe.Add([pscustomobject]@{ Program = $prog; Reason = $real[0] }) }
        elseif ($why.Count) { $unknown.Add($prog) }
    }
    if ($unsafe.Count) {
        $list = ($unsafe | Select-Object -First 5 | ForEach-Object { "$($_.Program) ($($_.Reason))" }) -join '; '
        if ($unsafe.Count -gt 5) { $list += " und $($unsafe.Count - 5) weitere" }
        Add-Result 'EDEP-NET-10' 'FAIL' "$($unsafe.Count) freigegebene Programme für Nicht-Admins änderbar: $list"
    }
    elseif ($unknown.Count) {
        Add-Result 'EDEP-NET-10' 'UNKNOWN' "Keine änderbaren Programmpfade gefunden; $($unknown.Count) Pfad(e) ohne Adminrechte nicht prüfbar (z. B. $($unknown[0]))"
    }
    else { Add-Result 'EDEP-NET-10' 'PASS' "$($allowPrograms.Count) freigegebene Programmpfade nur durch Admins änderbar" }

    # --- EDEP-ID-01 --------------------------------------------------------
    if (-not $isAdmin) { Add-Result 'EDEP-ID-01' 'UNKNOWN' 'App-Control-Status nur mit Adminrechten lesbar' }
    else {
        try {
            $raw = Invoke-EdepNative { CiTool.exe --list-policies -json } | Out-String
            $ci = $raw | ConvertFrom-Json -ErrorAction Stop
            if ($ci.OperationResult -eq -2147024891) { throw 'Zugriff verweigert (Adminrechte nötig)' }
            if ($null -eq $ci.Policies) { throw "Unerwartete CiTool-Ausgabe (OperationResult=$($ci.OperationResult))" }
            $active = @($ci.Policies | Where-Object { $_.IsEnforced -and -not $_.IsSystemPolicy })
            if ($active.Count -eq 0) {
                Add-Result 'EDEP-ID-01' 'FAIL' 'Keine aktive, nicht-systemeigene App-Control-Richtlinie'
            }
            else {
                $names = ($active | ForEach-Object {
                    $mode = if ((@($_.PolicyOptions) -join ' ') -match 'Audit') { 'Audit' } else { 'Erzwingend' }
                    "$($_.FriendlyName) [$mode]"
                }) -join '; '
                Add-Result 'EDEP-ID-01' 'PASS' "Aktiv: $names"
            }
        }
        catch { Add-Result 'EDEP-ID-01' 'FAIL' "App-Control-Status nicht ermittelbar: $($_.Exception.Message)" }
    }

    # --- EDEP-TEL-01 -------------------------------------------------------
    $tel = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' -Name AllowTelemetry -ErrorAction SilentlyContinue
    $ed = Get-EdepEditionSupportsSecurityTelemetry
    if (-not $tel) { Add-Result 'EDEP-TEL-01' 'FAIL' 'Richtlinie AllowTelemetry nicht gesetzt (Windows-Standard: Optional/Full möglich)' }
    elseif ($tel.AllowTelemetry -eq 0 -and $ed.Supported) { Add-Result 'EDEP-TEL-01' 'PASS' 'AllowTelemetry=0, wirksam: Security' }
    elseif ($tel.AllowTelemetry -eq 0) { Add-Result 'EDEP-TEL-01' 'WARN' "AllowTelemetry=0, wirksam auf '$($ed.EditionId)': 1 (Required) — niedrigste Stufe dieser Edition" }
    elseif ($tel.AllowTelemetry -eq 1 -and -not $ed.Supported) { Add-Result 'EDEP-TEL-01' 'PASS' "AllowTelemetry=1 (Required), niedrigste Stufe für '$($ed.EditionId)'" }
    else { Add-Result 'EDEP-TEL-01' 'FAIL' "AllowTelemetry=$($tel.AllowTelemetry) ist nicht die niedrigste Stufe" }

    # --- EDEP-TEL-02 -------------------------------------------------------
    $present = @($EdepTelemetryServices | Where-Object { Get-Service -Name $_ -ErrorAction SilentlyContinue })
    $missing = @($present | Where-Object { $blockedServices -notcontains $_.ToLowerInvariant() })
    # Dienstregeln wirken nur bei SID-Typ RESTRICTED/UNRESTRICTED (SPEC Q-08).
    $noSid = @($present | Where-Object { (Get-EdepServiceSidType $_) -notin 'RESTRICTED', 'UNRESTRICTED' })
    if ($missing) { Add-Result 'EDEP-TEL-02' 'FAIL' "Ohne ausgehende Blockregel: $($missing -join ', ')" }
    elseif ($noSid) { Add-Result 'EDEP-TEL-02' 'FAIL' "Blockregel wirkungslos, Dienst-SID-Typ nicht RESTRICTED/UNRESTRICTED: $($noSid -join ', ')" }
    else { Add-Result 'EDEP-TEL-02' 'PASS' "Ausgehend blockiert (Dienst-SID wirksam): $($present -join ', ')" }

    # --- EDEP-TEL-03 -------------------------------------------------------
    $wrong = $EdepRegistrySettings | Where-Object { $_.Id -eq 'EDEP-TEL-03' } | Where-Object {
        $v = Get-ItemProperty -Path $_.Path -Name $_.Name -ErrorAction SilentlyContinue
        -not $v -or $v.($_.Name) -ne $_.Value
    }
    if ($wrong) { Add-Result 'EDEP-TEL-03' 'FAIL' "Nicht gesetzt: $(($wrong | ForEach-Object { $_.Name }) -join ', ')" }
    else { Add-Result 'EDEP-TEL-03' 'PASS' 'Werbe-ID und Aktivitätsverlauf per Richtlinie deaktiviert' }

    # --- EDEP-TEL-04 -------------------------------------------------------
    $problems = @()
    $outboundBlocked = @($profiles | Where-Object { [string]$_.DefaultOutboundAction -eq 'Block' }).Count -gt 0
    $allowServices = @()
    if ($outboundBlocked) {
        $allowServices = @(Get-NetFirewallRule -PolicyStore ActiveStore -Direction Outbound -Action Allow -Enabled True -ErrorAction SilentlyContinue |
            Get-NetFirewallServiceFilter -ErrorAction SilentlyContinue | ForEach-Object { ([string]$_.Service).ToLowerInvariant() })
    }
    foreach ($svc in $EdepRequiredServices) {
        $n = $svc.Name.ToLowerInvariant()
        if ($blockedServices -contains $n) { $problems += "$($svc.Name) blockiert" }
        elseif ($outboundBlocked -and ($allowServices -notcontains $n)) { $problems += "$($svc.Name) ohne Erlaubnisregel" }
        elseif ($outboundBlocked -and (Get-EdepServiceSidType $svc.Name) -notin 'RESTRICTED', 'UNRESTRICTED') {
            $problems += "$($svc.Name): Erlaubnisregel wirkungslos (Dienst-SID-Typ)"
        }
    }
    $defenderExe = Get-EdepDefenderPrograms | Select-Object -First 1
    if ($outboundBlocked -and $defenderExe) {
        $allowPrograms = @(Get-NetFirewallRule -PolicyStore ActiveStore -Direction Outbound -Action Allow -Enabled True -ErrorAction SilentlyContinue |
            Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue | ForEach-Object { ConvertTo-EdepComparablePath $_.Program })
        if ($allowPrograms -notcontains (ConvertTo-EdepComparablePath $defenderExe)) {
            $problems += 'Defender-Plattform aktualisiert, Regel veraltet (Install-EdepL1.ps1 erneut ausführen)'
        }
    }
    if ($problems) { Add-Result 'EDEP-TEL-04' 'FAIL' ($problems -join '; ') }
    else { Add-Result 'EDEP-TEL-04' 'PASS' 'Update- und Schutzdienste erreichbar' }

    # --- EDEP-LOG-01 -------------------------------------------------------
    $problems = @()
    $bad = $profiles | Where-Object { [string]$_.LogBlocked -ne 'True' }
    if ($bad) { $problems += "LogBlocked aus: $($bad.Name -join ', ')" }
    $auditKnown = $true
    if (-not $isAdmin) { $auditKnown = $false }
    else {
        # Das /backup-Format enthält die sprachunabhängige Spalte "Setting Value" (Spalte 7):
        # 0 keine, 1 Erfolg, 2 Fehler, 3 beides. Die Sicherung wird nur gelesen und danach gelöscht.
        $auditTmp = Join-Path ([IO.Path]::GetTempPath()) "edep-auditpol-$PID.csv"
        Invoke-EdepNative { auditpol.exe /backup /file:$auditTmp } | Out-Null
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path $auditTmp)) { $problems += 'auditpol nicht lesbar' }
        else {
            $guid = $AuditFilteringPlatformConnection.Trim('{}')
            $row = Get-Content $auditTmp | Where-Object { $_ -match [regex]::Escape($guid) } | Select-Object -First 1
            Remove-Item $auditTmp -Force -ErrorAction SilentlyContinue
            $value = if ($row) { [int](($row -split ',')[6]) } else { 0 }
            if (($value -band 2) -eq 0) { $problems += 'Ereignis 5157 (Fehler) nicht aktiviert' }
        }
    }
    if ($problems) { Add-Result 'EDEP-LOG-01' 'FAIL' ($problems -join '; ') }
    elseif (-not $auditKnown) { Add-Result 'EDEP-LOG-01' 'UNKNOWN' 'Firewall-Log aktiv; Überwachungsrichtlinie nur mit Adminrechten lesbar' }
    else { Add-Result 'EDEP-LOG-01' 'PASS' 'Firewall-Log und Ereignis 5157 aktiv' }

    # --- EDEP-LOG-02 -------------------------------------------------------
    $remote = $profiles | Where-Object { ([Environment]::ExpandEnvironmentVariables([string]$_.LogFileName)) -like '\\*' }
    if ($remote) { Add-Result 'EDEP-LOG-02' 'FAIL' "Firewall-Log auf Netzwerkpfad: $($remote.Name -join ', ')" }
    else { Add-Result 'EDEP-LOG-02' 'PASS' 'Firewall-Log lokal' }

    # --- EDEP-LOG-06 -------------------------------------------------------
    $bitsLog = Get-WinEvent -ListLog $BitsClientLog -ErrorAction SilentlyContinue
    if (-not $bitsLog) { Add-Result 'EDEP-LOG-06' 'FAIL' "Protokoll $BitsClientLog nicht vorhanden" }
    elseif (-not $bitsLog.IsEnabled) { Add-Result 'EDEP-LOG-06' 'FAIL' "Protokoll $BitsClientLog deaktiviert: BITS-Umgehung (B-01) bliebe unbemerkt" }
    else { Add-Result 'EDEP-LOG-06' 'PASS' "BITS-Jobs werden protokolliert ($BitsClientLog)" }

    # --- EDEP-OPS-01 -------------------------------------------------------
    $backup = Get-ChildItem -Path $EdepBackupRoot -Directory -ErrorAction SilentlyContinue |
        Where-Object { (Test-Path (Join-Path $_.FullName 'manifest.json')) -and (Test-Path (Join-Path $_.FullName 'firewall.wfw')) } |
        Sort-Object Name | Select-Object -First 1
    if ($backup) { Add-Result 'EDEP-OPS-01' 'PASS' "Sicherung vorhanden: $($backup.FullName)" }
    else { Add-Result 'EDEP-OPS-01' 'FAIL' "Keine EDEP-Sicherung unter $EdepBackupRoot" }

    $results
}
