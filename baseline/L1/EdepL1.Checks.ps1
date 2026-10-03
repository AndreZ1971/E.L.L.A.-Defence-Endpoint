# Prüflogik für EDEP L1. Wird von Test-EdepL1.ps1 und Invoke-EdepAudit gemeinsam genutzt.
# Setzt EdepL1.Common.ps1 und EdepStrings.ps1 voraus. Ändert nichts am System.
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
    param(
        # EDEP-TEL-04: zusätzlich die Wirkung messen (Update-Suche), nicht nur die Regeln prüfen.
        [switch]$ProbeUpdates
    )

    $results = [System.Collections.Generic.List[object]]::new()
    function Add-Result([string]$Id, [string]$Status, [string]$Key, [object[]]$Arguments = @()) {
        $results.Add([pscustomobject]@{ Id = $Id; Status = $Status; Detail = (Get-EdepText $Key $Arguments) })
    }

    $isAdmin = Test-EdepIsAdmin
    $profiles = Get-NetFirewallProfile -PolicyStore ActiveStore

    # --- EDEP-NET-01 -------------------------------------------------------
    $bad = $profiles | Where-Object { -not $_.Enabled -or [string]$_.DefaultInboundAction -ne 'Block' }
    if ($bad) { Add-Result 'EDEP-NET-01' 'FAIL' 'net01.fail' @(($bad.Name -join ', ')) }
    else { Add-Result 'EDEP-NET-01' 'PASS' 'net01.pass' }

    # --- EDEP-NET-02 -------------------------------------------------------
    $stealthRoots = @($FirewallPolicyProfileKeys | ForEach-Object { "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\$_" }) +
                    @($FirewallProfileKeys.Values | ForEach-Object { "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\$_" })
    $stealthOff = foreach ($root in $stealthRoots) {
        $v = Get-ItemProperty -Path $root -Name DisableStealthMode -ErrorAction SilentlyContinue
        if ($v -and $v.DisableStealthMode -ne 0) { $root }
    }
    if ($stealthOff) { Add-Result 'EDEP-NET-02' 'FAIL' 'net02.fail' @(($stealthOff -join '; ')) }
    else { Add-Result 'EDEP-NET-02' 'PASS' 'net02.pass' }

    # --- EDEP-NET-03 -------------------------------------------------------
    $allowCount = (Get-NetFirewallRule -PolicyStore ActiveStore -Direction Outbound -Action Allow -Enabled True -ErrorAction SilentlyContinue | Measure-Object).Count
    $bad = $profiles | Where-Object { [string]$_.DefaultOutboundAction -ne 'Block' }
    if ($bad) { Add-Result 'EDEP-NET-03' 'FAIL' 'net03.fail' @(($bad.Name -join ', ')) }
    else {
        # Die Einstellung allein genügt nicht: Eine uneingeschränkte Erlaubnisregel hebt die Sperre auf (Abweichung 8).
        $openRules = @(Get-EdepUnrestrictedOutboundAllowRule)
        if ($openRules.Count) {
            $names = ($openRules | Select-Object -First 3) -join ', '
            if ($openRules.Count -gt 3) { $names += Get-EdepText 'more' @($openRules.Count - 3) }
            Add-Result 'EDEP-NET-03' 'FAIL' 'net03.open' @($names)
        }
        else { Add-Result 'EDEP-NET-03' 'PASS' 'net03.pass' @($allowCount) }
    }

    # Ausgehende Blockregeln einmal einsammeln (Programm- und Dienstfilter).
    $outBlock = @(Get-NetFirewallRule -PolicyStore ActiveStore -Direction Outbound -Action Block -Enabled True -ErrorAction SilentlyContinue)
    $blockedPrograms = @($outBlock | Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue |
        ForEach-Object { ConvertTo-EdepComparablePath $_.Program })
    $blockedServices = @($outBlock | Get-NetFirewallServiceFilter -ErrorAction SilentlyContinue |
        ForEach-Object { ([string]$_.Service).ToLowerInvariant() })

    # --- EDEP-NET-04 -------------------------------------------------------
    $lolbins = @(Get-EdepLolbinPaths)
    $missing = @($lolbins | Where-Object { $blockedPrograms -notcontains (ConvertTo-EdepComparablePath $_) })
    if ($missing.Count) {
        $short = @($missing | ForEach-Object { Split-Path $_ -Leaf } | Sort-Object -Unique)
        $names = ($short | Select-Object -First 8) -join ', '
        if ($short.Count -gt 8) { $names += Get-EdepText 'more' @($short.Count - 8) }
        Add-Result 'EDEP-NET-04' 'FAIL' 'net04.fail' @($missing.Count, $lolbins.Count, $names)
    }
    else {
        # Blockregeln gelten nicht gegen "Authenticated Bypass" (SPEC Q-05, Umgehung B-05).
        $bypass = @(Get-NetFirewallRule -PolicyStore ActiveStore -Direction Outbound -Action Allow -Enabled True -ErrorAction SilentlyContinue |
            Where-Object { ($_ | Get-NetFirewallSecurityFilter -ErrorAction SilentlyContinue).OverrideBlockRules })
        if ($bypass.Count) { Add-Result 'EDEP-NET-04' 'FAIL' 'net04.bypass' @((($bypass.DisplayName | Select-Object -First 5) -join ', ')) }
        else { Add-Result 'EDEP-NET-04' 'PASS' 'net04.pass' @($lolbins.Count) }
    }

    # --- EDEP-NET-05 -------------------------------------------------------
    $inBlockPublic = @(Get-NetFirewallRule -PolicyStore ActiveStore -Direction Inbound -Action Block -Enabled True -ErrorAction SilentlyContinue |
        Where-Object { Test-EdepProfileMatch $_ 'Public' })
    $blockedPorts = @($inBlockPublic | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue |
        Where-Object { [string]$_.Protocol -in 'TCP', 'Any' } |
        ForEach-Object { $_.LocalPort } | ForEach-Object { [string]$_ })
    $missing = @($EdepPublicInboundBlockPorts | Where-Object { ($blockedPorts -notcontains $_) -and ($blockedPorts -notcontains 'Any') })
    if ($missing.Count) { Add-Result 'EDEP-NET-05' 'FAIL' 'net05.fail' @(($missing -join ', ')) }
    else { Add-Result 'EDEP-NET-05' 'PASS' 'net05.pass' @(($EdepPublicInboundBlockPorts -join ', ')) }

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
        $real = @($why | Where-Object { -not ([string]$_).StartsWith($EdepAclUnknownMarker) })
        if ($real.Count) { $unsafe.Add([pscustomobject]@{ Program = $prog; Reason = $real[0] }) }
        elseif ($why.Count) { $unknown.Add($prog) }
    }
    if ($unsafe.Count) {
        $list = ($unsafe | Select-Object -First 5 | ForEach-Object { "$($_.Program) ($($_.Reason))" }) -join '; '
        if ($unsafe.Count -gt 5) { $list += Get-EdepText 'more' @($unsafe.Count - 5) }
        Add-Result 'EDEP-NET-10' 'FAIL' 'net10.fail' @($unsafe.Count, $list)
    }
    elseif ($unknown.Count) { Add-Result 'EDEP-NET-10' 'UNKNOWN' 'net10.unknown' @($unknown.Count, $unknown[0]) }
    else { Add-Result 'EDEP-NET-10' 'PASS' 'net10.pass' @($allowPrograms.Count) }

    # --- EDEP-ID-01 --------------------------------------------------------
    if (-not $isAdmin) { Add-Result 'EDEP-ID-01' 'UNKNOWN' 'id01.noadmin' }
    else {
        try {
            $raw = Invoke-EdepNative { CiTool.exe --list-policies -json } | Out-String
            $ci = $raw | ConvertFrom-Json -ErrorAction Stop
            if ($ci.OperationResult -eq -2147024891) { throw (Get-EdepText 'id01.denied') }
            if ($null -eq $ci.Policies) { throw (Get-EdepText 'id01.unexpected' @($ci.OperationResult)) }
            $active = @($ci.Policies | Where-Object { $_.IsEnforced -and -not $_.IsSystemPolicy })
            if ($active.Count -eq 0) { Add-Result 'EDEP-ID-01' 'FAIL' 'id01.fail' }
            else {
                $names = ($active | ForEach-Object {
                    $mode = if ((@($_.PolicyOptions) -join ' ') -match 'Audit') { Get-EdepText 'mode.audit' } else { Get-EdepText 'mode.enforced' }
                    "$($_.FriendlyName) [$mode]"
                }) -join '; '
                Add-Result 'EDEP-ID-01' 'PASS' 'id01.pass' @($names)
            }
        }
        catch { Add-Result 'EDEP-ID-01' 'FAIL' 'id01.error' @($_.Exception.Message) }
    }

    # --- EDEP-TEL-01 -------------------------------------------------------
    $tel = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' -Name AllowTelemetry -ErrorAction SilentlyContinue
    $ed = Get-EdepEditionSupportsSecurityTelemetry
    if (-not $tel) { Add-Result 'EDEP-TEL-01' 'FAIL' 'tel01.notset' }
    elseif ($tel.AllowTelemetry -eq 0 -and $ed.Supported) { Add-Result 'EDEP-TEL-01' 'PASS' 'tel01.pass0' }
    elseif ($tel.AllowTelemetry -eq 0) { Add-Result 'EDEP-TEL-01' 'WARN' 'tel01.warn' @($ed.EditionId) }
    elseif ($tel.AllowTelemetry -eq 1 -and -not $ed.Supported) { Add-Result 'EDEP-TEL-01' 'PASS' 'tel01.pass1' @($ed.EditionId) }
    else { Add-Result 'EDEP-TEL-01' 'FAIL' 'tel01.fail' @($tel.AllowTelemetry) }

    # --- EDEP-TEL-02 -------------------------------------------------------
    $present = @($EdepTelemetryServices | Where-Object { Get-Service -Name $_ -ErrorAction SilentlyContinue })
    $missing = @($present | Where-Object { $blockedServices -notcontains $_.ToLowerInvariant() })
    # Dienstregeln wirken nur bei SID-Typ RESTRICTED/UNRESTRICTED (SPEC Q-08).
    $noSid = @($present | Where-Object { (Get-EdepServiceSidType $_) -notin 'RESTRICTED', 'UNRESTRICTED' })
    if ($missing.Count) { Add-Result 'EDEP-TEL-02' 'FAIL' 'tel02.missing' @(($missing -join ', ')) }
    elseif ($noSid.Count) { Add-Result 'EDEP-TEL-02' 'FAIL' 'tel02.nosid' @(($noSid -join ', ')) }
    else { Add-Result 'EDEP-TEL-02' 'PASS' 'tel02.pass' @(($present -join ', ')) }

    # --- EDEP-TEL-03 -------------------------------------------------------
    $wrong = @($EdepRegistrySettings | Where-Object { $_.Id -eq 'EDEP-TEL-03' } | Where-Object {
        $v = Get-ItemProperty -Path $_.Path -Name $_.Name -ErrorAction SilentlyContinue
        -not $v -or $v.($_.Name) -ne $_.Value
    })
    if ($wrong.Count) { Add-Result 'EDEP-TEL-03' 'FAIL' 'tel03.fail' @((($wrong | ForEach-Object { $_.Name }) -join ', ')) }
    else { Add-Result 'EDEP-TEL-03' 'PASS' 'tel03.pass' }

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
        if ($blockedServices -contains $n) { $problems += Get-EdepText 'tel04.blocked' @($svc.Name) }
        elseif ($outboundBlocked -and ($allowServices -notcontains $n)) { $problems += Get-EdepText 'tel04.noallow' @($svc.Name) }
        elseif ($outboundBlocked -and (Get-EdepServiceSidType $svc.Name) -notin 'RESTRICTED', 'UNRESTRICTED') {
            $problems += Get-EdepText 'tel04.nosid' @($svc.Name)
        }
    }
    $defenderExe = Get-EdepDefenderPrograms | Select-Object -First 1
    if ($outboundBlocked -and $defenderExe) {
        $allowedPaths = @(Get-NetFirewallRule -PolicyStore ActiveStore -Direction Outbound -Action Allow -Enabled True -ErrorAction SilentlyContinue |
            Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue | ForEach-Object { ConvertTo-EdepComparablePath $_.Program })
        if ($allowedPaths -notcontains (ConvertTo-EdepComparablePath $defenderExe)) { $problems += Get-EdepText 'tel04.defender' }
    }
    if ($outboundBlocked) {
        # Dienstregeln erlauben wuauserv und BITS nicht (E-84); erreichbar werden die Update-Ziele nur über die
        # Domainregeln (-AllowWindowsUpdate) und den Netzwerkschutz, den sie voraussetzen (E-88).
        $updateRules = @(Get-NetFirewallRule -PolicyStore ActiveStore -Direction Outbound -Action Allow -Enabled True -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName -like "$EdepUpdateRulePrefix*" })
        $np = if ($isAdmin) { Get-EdepNetworkProtection } else { 2 }   # ohne Adminrechte nicht prüfbar, dann nicht werten
        switch (Get-EdepUpdateDomainStatus -RuleCount $updateRules.Count -NetworkProtection $np) {
            'nodomains' { $problems += Get-EdepText 'tel04.nodomains' }
            'nonp'      { $problems += Get-EdepText 'tel04.nonp' }
        }
    }
    if ($problems) { $results.Add([pscustomobject]@{ Id = 'EDEP-TEL-04'; Status = 'FAIL'; Detail = ($problems -join '; ') }) }
    elseif (-not $outboundBlocked) { Add-Result 'EDEP-TEL-04' 'PASS' 'tel04.pass' }
    else {
        # Lauf 1 (Abweichungen 6, 7): Regeln und SID-Typ waren in Ordnung, die Updates aber nicht erreichbar.
        # Deshalb gilt unter "ausgehend Block" nur eine Messung als Beleg; ohne Messung bleibt es bei WARN.
        $probe = if ($ProbeUpdates -and $isAdmin) { Test-EdepUpdateReachable } else { $null }
        $o = Get-EdepUpdateProbeOutcome -Probed ([bool]$probe) -Probe $probe
        Add-Result 'EDEP-TEL-04' $o.Status $o.Key $o.Arguments
    }

    # --- EDEP-LOG-01 -------------------------------------------------------
    $problems = @()
    $bad = $profiles | Where-Object { [string]$_.LogBlocked -ne 'True' }
    if ($bad) { $problems += Get-EdepText 'log01.logblocked' @(($bad.Name -join ', ')) }
    if ($isAdmin) {
        # Das /backup-Format enthält die sprachunabhängige Spalte "Setting Value" (Spalte 7, EVIDENCE E-16):
        # 0 keine, 1 Erfolg, 2 Fehler, 3 beides. Die Sicherung wird nur gelesen und danach gelöscht.
        $auditTmp = Join-Path ([IO.Path]::GetTempPath()) "edep-auditpol-$PID.csv"
        Invoke-EdepNative { auditpol.exe /backup /file:$auditTmp } | Out-Null
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path $auditTmp)) { $problems += Get-EdepText 'log01.auditpol' }
        else {
            $guid = $AuditFilteringPlatformConnection.Trim('{}')
            $row = Get-Content $auditTmp | Where-Object { $_ -match [regex]::Escape($guid) } | Select-Object -First 1
            Remove-Item $auditTmp -Force -ErrorAction SilentlyContinue
            $value = if ($row) { [int](($row -split ',')[6]) } else { 0 }
            if (($value -band 2) -eq 0) { $problems += Get-EdepText 'log01.5157' }
        }
    }
    if ($problems) { $results.Add([pscustomobject]@{ Id = 'EDEP-LOG-01'; Status = 'FAIL'; Detail = ($problems -join '; ') }) }
    elseif (-not $isAdmin) { Add-Result 'EDEP-LOG-01' 'UNKNOWN' 'log01.unknown' }
    else {
        # Empfehlung (BSI SiSyPHuS AP10), keine Anforderung der SPEC: zu kleines Protokoll gibt WARN, nicht FAIL.
        $small = @(Get-EdepSmallLogProfile $profiles)
        if ($small.Count) { Add-Result 'EDEP-LOG-01' 'WARN' 'log01.smalllog' @(($small -join ', ')) }
        else { Add-Result 'EDEP-LOG-01' 'PASS' 'log01.pass' }
    }

    # --- EDEP-LOG-02 -------------------------------------------------------
    $remote = $profiles | Where-Object { ([Environment]::ExpandEnvironmentVariables([string]$_.LogFileName)) -like '\\*' }
    if ($remote) { Add-Result 'EDEP-LOG-02' 'FAIL' 'log02.fail' @(($remote.Name -join ', ')) }
    else { Add-Result 'EDEP-LOG-02' 'PASS' 'log02.pass' }

    # --- EDEP-LOG-06 -------------------------------------------------------
    $bitsLog = Get-WinEvent -ListLog $BitsClientLog -ErrorAction SilentlyContinue
    if (-not $bitsLog) { Add-Result 'EDEP-LOG-06' 'FAIL' 'log06.missing' @($BitsClientLog) }
    elseif (-not $bitsLog.IsEnabled) { Add-Result 'EDEP-LOG-06' 'FAIL' 'log06.disabled' @($BitsClientLog) }
    else { Add-Result 'EDEP-LOG-06' 'PASS' 'log06.pass' @($BitsClientLog) }

    # --- EDEP-OPS-01 -------------------------------------------------------
    $backup = Get-ChildItem -Path $EdepBackupRoot -Directory -ErrorAction SilentlyContinue |
        Where-Object { (Test-Path (Join-Path $_.FullName 'manifest.json')) -and (Test-Path (Join-Path $_.FullName 'firewall.wfw')) } |
        Sort-Object Name | Select-Object -First 1
    if ($backup) { Add-Result 'EDEP-OPS-01' 'PASS' 'ops01.pass' @($backup.FullName) }
    else { Add-Result 'EDEP-OPS-01' 'FAIL' 'ops01.fail' @($EdepBackupRoot) }

    $results
}
