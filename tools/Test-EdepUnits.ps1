<#
.SYNOPSIS
    Einheitentests für die Prüflogik von EDEP L1. Ändert nichts am System, braucht keine Adminrechte.

.DESCRIPTION
    Sichert Fehler ab, die der erste Durchlauf in der Windows-Sandbox gezeigt hat (docs: conformance/runs/):
      - NET-10: "Delete" an der Laufwerkswurzel darf nicht zählen (Abweichung 1)
      - NET-03: eine uneingeschränkte ausgehende Erlaubnisregel hebt die Standardsperre auf (Abweichung 8)
    Exit-Code 0 nur, wenn alle Tests bestehen.
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$l1 = Join-Path (Split-Path $PSScriptRoot -Parent) 'baseline\L1'
. (Join-Path $l1 'EdepStrings.ps1')
. (Join-Path $l1 'EdepL1.Common.ps1')
Set-EdepLanguage de

$script:failed = 0
function Assert-That([string]$Name, [bool]$Condition) {
    if ($Condition) { Write-Host "PASS  $Name" -ForegroundColor Green }
    else { Write-Host "FAIL  $Name" -ForegroundColor Red; $script:failed++ }
}

# ---------------------------------------------------------------------------
# NET-03: Test-EdepRuleUnrestricted
# ---------------------------------------------------------------------------
function New-Rule([hashtable]$Override = @{}) {
    $r = [ordered]@{
        Program = 'Any'; Package = ''; PackageFamilyName = ''; PolicyAppId = ''; Owner = ''
        LocalUser = 'Any'; Service = 'Any'; Protocol = 'Any'; RemotePort = 'Any'; RemoteAddress = 'Any'
    }
    foreach ($k in $Override.Keys) { $r[$k] = $Override[$k] }
    [pscustomobject]$r
}

Assert-That 'NET-03: Regel wie "Container: allow outbound" gilt als uneingeschränkt' (Test-EdepRuleUnrestricted (New-Rule))
Assert-That 'NET-03: alles TCP an alle Ziele gilt als uneingeschränkt'                (Test-EdepRuleUnrestricted (New-Rule @{ Protocol = 'TCP' }))
Assert-That 'NET-03: Store-App-Regel (PackageFamilyName, Owner) gilt NICHT'           (-not (Test-EdepRuleUnrestricted (New-Rule @{ PackageFamilyName = 'Microsoft.Windows.NarratorQuickStart_8wekyb3d8bbwe'; Owner = 'S-1-5-21-1-2-3-1001' })))
Assert-That 'NET-03: Regel mit Programm gilt NICHT'                                   (-not (Test-EdepRuleUnrestricted (New-Rule @{ Program = 'C:\Program Files\x\x.exe' })))
Assert-That 'NET-03: Regel mit Dienst gilt NICHT'                                     (-not (Test-EdepRuleUnrestricted (New-Rule @{ Service = 'wuauserv' })))
Assert-That 'NET-03: Regel mit Port 443 gilt NICHT'                                   (-not (Test-EdepRuleUnrestricted (New-Rule @{ RemotePort = '443' })))
Assert-That 'NET-03: Regel nur für UDP gilt NICHT'                                    (-not (Test-EdepRuleUnrestricted (New-Rule @{ Protocol = 'UDP' })))
Assert-That 'NET-03: Regel nur für das lokale Subnetz gilt NICHT'                     (-not (Test-EdepRuleUnrestricted (New-Rule @{ RemoteAddress = 'LocalSubnet' })))
Assert-That 'NET-03: Regel mit Besitzer gilt NICHT'                                   (-not (Test-EdepRuleUnrestricted (New-Rule @{ Owner = 'S-1-5-21-1-2-3-1001' })))
Assert-That 'NET-03: Regel mit Benutzerbindung gilt NICHT'                            (-not (Test-EdepRuleUnrestricted (New-Rule @{ LocalUser = 'D:(A;;CC;;;S-1-5-21-1-2-3-1001)' })))
Assert-That 'NET-03: Regel mit App-Control-Tag gilt NICHT'                            (-not (Test-EdepRuleUnrestricted (New-Rule @{ PolicyAppId = 'edep:allow' })))

# ---------------------------------------------------------------------------
# NET-10: Get-EdepWritableByNonAdmin an der Laufwerkswurzel
# Nachbau der in der Sandbox gemessenen ACL von C:\ (Authentifizierte Benutzer: Modify, nur dieser Ordner).
# ---------------------------------------------------------------------------
function New-FakeRootAcl {
    $sec = New-Object System.Security.AccessControl.DirectorySecurity
    $sec.SetOwner([Security.Principal.SecurityIdentifier]'S-1-5-32-544')
    $rights = [System.Security.AccessControl.FileSystemRights]
    $allow = [System.Security.AccessControl.AccessControlType]::Allow
    $none = [System.Security.AccessControl.InheritanceFlags]::None
    $both = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit'
    $np = [System.Security.AccessControl.PropagationFlags]::None
    $io = [System.Security.AccessControl.PropagationFlags]::InheritOnly
    foreach ($sid in 'S-1-5-18', 'S-1-5-32-544') {
        $sec.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(([Security.Principal.SecurityIdentifier]$sid), $rights::FullControl, $both, $np, $allow)))
    }
    $au = [Security.Principal.SecurityIdentifier]'S-1-5-11'
    $sec.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($au, $rights::Modify, $none, $np, $allow)))
    $sec.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($au, $rights::Modify, $both, $io, $allow)))
    $sec
}

$systemDrive = $env:SystemDrive
$prog = Join-Path $env:SystemRoot 'System32\notepad.exe'
if (Test-Path -LiteralPath $prog) {
    # Get-Acl überlagern: nur die Laufwerkswurzel liefert die nachgebaute Liste, alles andere bleibt echt.
    function Get-Acl {
        param([string]$Path, [string]$LiteralPath)
        $p = if ($LiteralPath) { $LiteralPath } else { $Path }
        if ($p.TrimEnd('\') -eq $systemDrive) { return (New-FakeRootAcl) }
        Microsoft.PowerShell.Security\Get-Acl -LiteralPath $p
    }
    $r = @(Get-EdepWritableByNonAdmin $prog)
    Assert-That "NET-10: Windows-Programm trotz Modify auf $systemDrive\ nicht beanstandet" ($r.Count -eq 0)

    $tmp = Join-Path ([IO.Path]::GetTempPath()) 'edep-unit-net10'
    New-Item -ItemType Directory $tmp -Force | Out-Null
    $exe = Join-Path $tmp 'p.exe'
    Set-Content $exe 'x'
    $r = @(Get-EdepWritableByNonAdmin $exe)
    Assert-That 'NET-10: Programm in einem Benutzerordner wird weiterhin erkannt' ($r.Count -gt 0)
    Remove-Item $tmp -Recurse -Force -Confirm:$false
}
else {
    Assert-That "NET-10: Testprogramm $prog vorhanden" $false
}

# ---------------------------------------------------------------------------
# ID-01 / OPS-01: Get-EdepAppControlPolicyId (Lauf 1, Abweichung 5: eine Richtlinie je Installer-Aufruf)
# ---------------------------------------------------------------------------
$ciJson = @'
{"Policies":[
 {"FriendlyName":"EDEP L1 Audit","PolicyID":"f1bb1080-fc9c-42e2-bfd3-40bde156797e","IsEnforced":true},
 {"FriendlyName":"Microsoft Windows Driver Policy","PolicyID":"d2bda982-ccf6-4344-ac5b-0b44427b6816","IsEnforced":true},
 {"FriendlyName":"EDEP L1 Audit","PolicyID":"b37684d5-ef32-4ac4-9c87-0566458c34a3","IsEnforced":true},
 {"FriendlyName":"EDEP L1 Audit","PolicyID":"ad11e468-a63d-4ef2-85c8-cf402ed43b35","IsEnforced":true}]}
'@
$ids = @(Get-EdepAppControlPolicyId -Json $ciJson)
Assert-That 'ID-01: alle drei EDEP-Richtlinien werden gefunden' ($ids.Count -eq 3)
Assert-That 'ID-01: fremde Richtlinien werden nicht eingesammelt' ($ids -notcontains 'd2bda982-ccf6-4344-ac5b-0b44427b6816')
Assert-That 'ID-01: keine EDEP-Richtlinie ergibt eine leere Liste' (@(Get-EdepAppControlPolicyId -Json '{"Policies":[]}').Count -eq 0)
Assert-That 'ID-01: unlesbare Ausgabe ergibt eine leere Liste statt Fehler' (@(Get-EdepAppControlPolicyId -Json 'kein json').Count -eq 0)

# ---------------------------------------------------------------------------
# TEL-04: Wirkung statt nur Regeln (Lauf 1, Abweichungen 6 und 7)
# ---------------------------------------------------------------------------
$ok = Test-EdepUpdateReachable -Search { }
Assert-That 'TEL-04: gelungene Suche wird als Ok gemeldet' ($ok.Ok -eq $true)
$bad = Test-EdepUpdateReachable -Search { throw [System.Runtime.InteropServices.COMException]::new('Verbindung', [int]0x8024402F) }
Assert-That 'TEL-04: fehlgeschlagene Suche wird mit HRESULT gemeldet' (($bad.Ok -eq $false) -and ($bad.HResult -eq '0x8024402F'))

$o = Get-EdepUpdateProbeOutcome -Probed $false -Probe $null
Assert-That 'TEL-04: ohne Messung nie PASS (nur WARN)' (($o.Status -eq 'WARN') -and ($o.Key -eq 'tel04.noprobe'))
$o = Get-EdepUpdateProbeOutcome -Probed $true -Probe $bad
Assert-That 'TEL-04: fehlgeschlagene Messung ergibt FAIL mit Fehlercode' (($o.Status -eq 'FAIL') -and ($o.Arguments[0] -eq '0x8024402F'))
$o = Get-EdepUpdateProbeOutcome -Probed $true -Probe $ok
Assert-That 'TEL-04: gelungene Messung ergibt nur WARN (Zwischenspeicher möglich)' (($o.Status -eq 'WARN') -and ($o.Key -eq 'tel04.probeok'))
Assert-That 'TEL-04: Fehlertext nennt den Code' ((Get-EdepText 'tel04.probefail' @('0x8024402F')) -match '0x8024402F')

# ---------------------------------------------------------------------------
# TEL-04: Update-Domainregeln (-AllowWindowsUpdate, E-88)
# ---------------------------------------------------------------------------
Assert-That 'TEL-04: Domainliste ist nicht leer' ($EdepUpdateDomains.Count -ge 5)
Assert-That 'TEL-04: Domainliste ohne Duplikate' (@($EdepUpdateDomains | Select-Object -Unique).Count -eq $EdepUpdateDomains.Count)
Assert-That 'TEL-04: Domains sind Hostnamen (kein Schema, kein Pfad, Wildcard nur am Anfang)' (@($EdepUpdateDomains | Where-Object { $_ -notmatch '^(\*\.)?[a-z0-9-]+(\.[a-z0-9-]+)+$' }).Count -eq 0)
Assert-That 'TEL-04: Domainliste nennt Quelle und Stand' (($EdepUpdateDomainSource -match '^https://learn\.microsoft\.com/') -and ($EdepUpdateDomainDate -match '^\d{4}-\d{2}-\d{2}$'))

Assert-That 'TEL-04: ohne Regeln unter Block: nodomains' ((Get-EdepUpdateDomainStatus -RuleCount 0 -NetworkProtection 2) -eq 'nodomains')
Assert-That 'TEL-04: Regeln, aber Netzwerkschutz aus: nonp' ((Get-EdepUpdateDomainStatus -RuleCount 9 -NetworkProtection 0) -eq 'nonp')
Assert-That 'TEL-04: Regeln, Netzwerkschutz nicht verfügbar: nonp' ((Get-EdepUpdateDomainStatus -RuleCount 9 -NetworkProtection $null) -eq 'nonp')
Assert-That 'TEL-04: Regeln und Netzwerkschutz im Audit-Modus: ok' ((Get-EdepUpdateDomainStatus -RuleCount 9 -NetworkProtection 2) -eq 'ok')
Assert-That 'TEL-04: Regeln und Netzwerkschutz im Block-Modus: ok' ((Get-EdepUpdateDomainStatus -RuleCount 9 -NetworkProtection 1) -eq 'ok')

$kw = @(
    [pscustomobject]@{ Id = '{1}'; Keyword = '*.windowsupdate.com'; AutoResolve = $true }
    [pscustomobject]@{ Id = '{2}'; Keyword = 'contoso.com'; AutoResolve = $true }
    [pscustomobject]@{ Id = '{3}'; Keyword = 'emdl.ws.microsoft.com'; AutoResolve = $false }
)
$sel = @(Select-EdepUpdateKeyword $kw)
Assert-That 'TEL-04: es werden nur EDEP-Schlüsselwörter (Domain aus der Liste, AutoResolve) gewählt' (($sel.Count -eq 1) -and ($sel[0].Id -eq '{1}'))
Assert-That 'TEL-04: keine Schlüsselwörter ergibt eine leere Auswahl' (@(Select-EdepUpdateKeyword $null).Count -eq 0)
Assert-That 'Netzwerkschutz: Werte 0, 1, 2 werden zu Disabled, Enabled, AuditMode' (((Get-EdepNetworkProtectionName 0), (Get-EdepNetworkProtectionName 1), (Get-EdepNetworkProtectionName 2)) -join ',' -eq 'Disabled,Enabled,AuditMode')
Assert-That 'TEL-04: Texte nennen die Option' ((Get-EdepText 'tel04.nodomains') -match 'AllowWindowsUpdate')

# Restore: Wert für den Netzwerkschutz kommt aus der ältesten Sicherung, die ihn geändert hat (Lauf 2, Nachtest)
$old = [pscustomobject]@{ edep = '0.1.0' }   # Sicherung aus der Zeit vor der Option: kennt die Felder nicht
$m1 = [pscustomobject]@{ networkProtection = 0; networkProtectionChanged = $true }
$m2 = [pscustomobject]@{ networkProtection = 2; networkProtectionChanged = $false }
$m3 = [pscustomobject]@{ networkProtection = 1; networkProtectionChanged = $true }
Assert-That 'Restore: ohne Änderung durch EDEP wird nichts zurückgestellt' ($null -eq (Get-EdepNetworkProtectionRestoreValue @($old, $m2)))
Assert-That 'Restore: Wert der Sicherung, die geändert hat (auch hinter einer Sicherung ohne Feld)' ((Get-EdepNetworkProtectionRestoreValue @($old, $m1, $m2)) -eq 0)
Assert-That 'Restore: bei mehreren Änderungen zählt die älteste' ((Get-EdepNetworkProtectionRestoreValue @($m1, $m2, $m3)) -eq 0)
Assert-That 'Restore: keine Manifeste ergibt nichts zurückzustellen' ($null -eq (Get-EdepNetworkProtectionRestoreValue @()))

Write-Host ''
if ($script:failed) { Write-Host "$script:failed Test(s) fehlgeschlagen." -ForegroundColor Red; exit 1 }
Write-Host 'Alle Einheitentests bestanden.' -ForegroundColor Green
exit 0
