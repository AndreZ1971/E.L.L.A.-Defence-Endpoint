# Gemeinsame Definitionen für EDEP L1 (Install / Test / Restore).
# Wird per Dot-Sourcing geladen, nicht direkt ausführen.

$script:EdepVersion   = '0.1.0'
$script:EdepRuleGroup = 'EDEP-L1'
$script:EdepDataRoot  = Join-Path $env:ProgramData 'EDEP'
$script:EdepBackupRoot = Join-Path $script:EdepDataRoot 'backup'

# Überwachung "Filterplattformverbindung" (Ereignis 5157). GUID statt Namen, damit es auf jeder Sprachversion funktioniert.
$script:AuditFilteringPlatformConnection = '{0CCE9226-69AE-11D9-BED3-505054503030}'

# Gruppe "Kernnetzwerk" (DNS-Client, DHCP, ICMPv6/NDP) — sprachunabhängige Ressourcen-ID.
$script:CoreNetworkingGroup = '@FirewallAPI.dll,-25000'

# Firewall-Profile -> Registrierungsschlüssel (Private heißt intern StandardProfile).
$script:FirewallProfileKeys = [ordered]@{
    Domain  = 'DomainProfile'
    Private = 'StandardProfile'
    Public  = 'PublicProfile'
}

# EDEP-TEL-01 / EDEP-TEL-03
$script:EdepRegistrySettings = @(
    @{ Id = 'EDEP-TEL-01'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'; Name = 'AllowTelemetry';         Value = 0 }
    @{ Id = 'EDEP-TEL-03'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo'; Name = 'DisabledByGroupPolicy';  Value = 1 }
    @{ Id = 'EDEP-TEL-03'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System';          Name = 'PublishUserActivities';  Value = 0 }
    @{ Id = 'EDEP-TEL-03'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System';          Name = 'UploadUserActivities';   Value = 0 }
)

# EDEP-TEL-02
$script:EdepTelemetryServices = @('DiagTrack', 'dmwappushservice')

# EDEP-TEL-04: Dienste, die für Sicherheitsaktualisierungen erreichbar bleiben müssen.
$script:EdepRequiredServices = @(
    @{ Name = 'wuauserv'; Protocol = 'TCP'; Ports = @('80', '443') }
    @{ Name = 'BITS';     Protocol = 'TCP'; Ports = @('80', '443') }
    @{ Name = 'DoSvc';    Protocol = 'TCP'; Ports = @('80', '443') }
    @{ Name = 'CryptSvc'; Protocol = 'TCP'; Ports = @('80', '443') }
    @{ Name = 'W32Time';  Protocol = 'UDP'; Ports = @('123') }
)

# EDEP-NET-05: im Profil Public eingehend zu sperren.
$script:EdepPublicInboundBlockPorts = @('135', '445', '3389', '5985', '5986')

function Get-EdepLolbinPaths {
    # SPEC.md Anhang A. Liefert nur Pfade, die auf diesem System existieren.
    $sys = $env:SystemRoot
    $candidates = @(
        "$sys\System32\WindowsPowerShell\v1.0\powershell.exe"
        "$sys\SysWOW64\WindowsPowerShell\v1.0\powershell.exe"
        "$sys\System32\WindowsPowerShell\v1.0\powershell_ise.exe"
        "$sys\System32\curl.exe"
        "$sys\SysWOW64\curl.exe"
        "$sys\System32\certutil.exe"
        "$sys\SysWOW64\certutil.exe"
        "$sys\System32\bitsadmin.exe"
        "$sys\System32\mshta.exe"
        "$sys\SysWOW64\mshta.exe"
        "$sys\System32\rundll32.exe"
        "$sys\SysWOW64\rundll32.exe"
        "$sys\System32\regsvr32.exe"
        "$sys\SysWOW64\regsvr32.exe"
        "$sys\System32\wscript.exe"
        "$sys\System32\cscript.exe"
        "$sys\hh.exe"
    )
    foreach ($fw in 'Framework', 'Framework64') {
        $candidates += "$sys\Microsoft.NET\$fw\v4.0.30319\MSBuild.exe"
        $candidates += "$sys\Microsoft.NET\$fw\v4.0.30319\InstallUtil.exe"
    }
    $candidates | Where-Object { Test-Path -LiteralPath $_ }
}

function Get-EdepDefenderPrograms {
    # Aktuelle Defender-Plattform ermitteln; der Pfad ändert sich mit Plattform-Updates.
    $svc = Get-CimInstance Win32_Service -Filter "Name='WinDefend'" -ErrorAction SilentlyContinue
    $result = @()
    if ($svc -and $svc.PathName) {
        $exe = $svc.PathName.Trim('"')
        if (Test-Path -LiteralPath $exe) {
            $result += $exe
            $mpcmd = Join-Path (Split-Path $exe) 'MpCmdRun.exe'
            if (Test-Path -LiteralPath $mpcmd) { $result += $mpcmd }
        }
    }
    $smartscreen = "$env:SystemRoot\System32\smartscreen.exe"
    if (Test-Path -LiteralPath $smartscreen) { $result += $smartscreen }
    $result
}

function Invoke-EdepNative([scriptblock]$Block) {
    # PowerShell 5.1 macht aus stderr nativer Programme bei ErrorAction=Stop einen Abbruch.
    # Hier zählt nur $LASTEXITCODE; stderr wird verworfen.
    $ErrorActionPreference = 'Continue'
    & $Block 2>$null
}

function ConvertTo-EdepComparablePath([string]$Path) {
    if (-not $Path) { return '' }
    [Environment]::ExpandEnvironmentVariables($Path).ToLowerInvariant()
}

function Get-EdepEditionSupportsSecurityTelemetry {
    # AllowTelemetry=0 wirkt nur auf Enterprise, Education, IoT Enterprise und Server.
    $edition = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction SilentlyContinue).EditionID
    [pscustomobject]@{
        EditionId = $edition
        Supported = [bool]($edition -match 'Enterprise|Education|Server')
    }
}
