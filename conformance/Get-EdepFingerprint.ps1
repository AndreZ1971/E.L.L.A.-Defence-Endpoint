param([string]$Root, [string]$Out)

# Fingerabdruck des Firewall-/Richtlinienzustands (TESTPLAN-L1, Abschnitt 6). Nur lesend.
. (Join-Path $Root 'EdepStrings.ps1')
. (Join-Path $Root 'EdepL1.Common.ps1')

function Get-EdepFingerprint {
    $rules = @(Get-NetFirewallRule -PolicyStore ActiveStore -Enabled True -ErrorAction SilentlyContinue)
    $n = { param($d, $a) @($rules | Where-Object { [string]$_.Direction -eq $d -and [string]$_.Action -eq $a }).Count }

    $tmp = Join-Path ([IO.Path]::GetTempPath()) 'edep-fp-audit.csv'
    Invoke-EdepNative { auditpol.exe /backup /file:$tmp } | Out-Null
    $audit = $null
    if (Test-Path $tmp) {
        $row = Get-Content $tmp | Where-Object { $_ -match '0CCE9226-69AE-11D9-BED3-505054503030' } | Select-Object -First 1
        if ($row) { $audit = [int](($row -split ',')[6]) }
        Remove-Item $tmp -Force -ErrorAction SilentlyContinue
    }

    $ci = @()
    try {
        $j = Invoke-EdepNative { CiTool.exe --list-policies -json } | Out-String | ConvertFrom-Json
        $ci = @($j.Policies | Where-Object { $_.IsEnforced -and -not $_.IsSystemPolicy } | ForEach-Object { $_.FriendlyName })
    } catch { $ci = @('nicht lesbar') }

    $mp = Get-MpComputerStatus -ErrorAction SilentlyContinue
    $svc = Get-Service DiagTrack -ErrorAction SilentlyContinue

    [ordered]@{
        erzeugt          = (Get-Date).ToString('o')
        profile          = @(Get-NetFirewallProfile -PolicyStore ActiveStore | ForEach-Object {
            [ordered]@{ name = [string]$_.Name; enabled = [string]$_.Enabled; inbound = [string]$_.DefaultInboundAction
                        outbound = [string]$_.DefaultOutboundAction; logBlocked = [string]$_.LogBlocked } })
        regeln           = [ordered]@{
            ausgehendErlauben = (& $n 'Outbound' 'Allow'); ausgehendBlock = (& $n 'Outbound' 'Block')
            eingehendErlauben = (& $n 'Inbound' 'Allow');  eingehendBlock = (& $n 'Inbound' 'Block')
            gruppeEdepL1      = @(Get-NetFirewallRule -Group $EdepRuleGroup -ErrorAction SilentlyContinue).Count }
        registrierung    = @($EdepRegistrySettings | ForEach-Object {
            $v = Get-ItemProperty -Path $_.Path -Name $_.Name -ErrorAction SilentlyContinue
            [ordered]@{ wert = "$($_.Path)\$($_.Name)"; aktuell = $(if ($v) { $v.($_.Name) } else { $null }) } })
        audit5157        = $audit
        diagTrackStart   = $(if ($svc) { [string]$svc.StartType } else { $null })
        appControlEigene = $ci
        defender         = [ordered]@{ aktiv = $(if ($mp) { [bool]$mp.AntivirusEnabled } else { $null })
                                       plattform = $(if ($mp) { [string]$mp.AMProductVersion } else { $null }) }
    }
}

$fp = Get-EdepFingerprint
$fp | ConvertTo-Json -Depth 6 | Set-Content -Path $Out -Encoding UTF8
"Fingerabdruck geschrieben: $Out"
