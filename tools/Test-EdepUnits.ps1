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

Write-Host ''
if ($script:failed) { Write-Host "$script:failed Test(s) fehlgeschlagen." -ForegroundColor Red; exit 1 }
Write-Host 'Alle Einheitentests bestanden.' -ForegroundColor Green
exit 0
