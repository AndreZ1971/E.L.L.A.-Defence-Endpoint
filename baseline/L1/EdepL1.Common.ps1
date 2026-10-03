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

# Firewall-Profile -> lokale Registrierungsschlüssel (Private heißt intern StandardProfile).
$script:FirewallProfileKeys = [ordered]@{
    Domain  = 'DomainProfile'
    Private = 'StandardProfile'
    Public  = 'PublicProfile'
}
# Im Richtlinienpfad kommen für Private beide Namen vor (MS-GPFAS 2.2.3.2, SPEC Q-06).
$script:FirewallPolicyProfileKeys = @('DomainProfile', 'PrivateProfile', 'StandardProfile', 'PublicProfile')

# EDEP-LOG-06: Erkennung der Umgehung B-01 (BITS-Jobs).
$script:BitsClientLog = 'Microsoft-Windows-Bits-Client/Operational'

# EDEP-NET-10: Diese Konten dürfen Programme mit Netzfreigabe ändern.
# SYSTEM, Administratoren, TrustedInstaller.
# Präfix für "nicht lesbar" (nicht unsicher, nur unbekannt); sprachunabhängig.
$script:EdepAclUnknownMarker = '?: '

$script:EdepTrustedWriterSids = @(
    'S-1-5-18'
    'S-1-5-32-544'
    'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'
)

# EDEP-TEL-01 / EDEP-TEL-03
$script:EdepRegistrySettings = @(
    @{ Id = 'EDEP-TEL-01'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'; Name = 'AllowTelemetry';         Value = 0 }
    @{ Id = 'EDEP-TEL-03'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo'; Name = 'DisabledByGroupPolicy';  Value = 1 }
    @{ Id = 'EDEP-TEL-03'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System';          Name = 'PublishUserActivities';  Value = 0 }
    @{ Id = 'EDEP-TEL-03'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System';          Name = 'UploadUserActivities';   Value = 0 }
    @{ Id = 'EDEP-TEL-03'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System';          Name = 'EnableActivityFeed';     Value = 0 }
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

function Get-EdepServiceSidType([string]$Name) {
    # Dienstbezogene Firewall-Regeln wirken nur bei RESTRICTED/UNRESTRICTED (SPEC Q-08).
    $out = (Invoke-EdepNative { sc.exe qsidtype $Name }) -join ' '
    if ($out -match 'SERVICE_SID_TYPE:\s*(\w+)') { return $Matches[1] }
    $null
}

function Get-EdepWritableByNonAdmin([string]$Path) {
    # EDEP-NET-10: Liefert die Gründe, warum Nicht-Administratoren die Datei oder einen
    # übergeordneten Ordner ändern könnten. Leere Liste = nur Admin/SYSTEM/TrustedInstaller.
    # Datei:          WriteData(2), AppendData(4), Delete(65536), ChangePermissions(262144), TakeOwnership(524288)
    # direkter Ordner: CreateFiles(2, DLL-Sideloading), DeleteSubdirectoriesAndFiles(64), Delete, ChangePermissions, TakeOwnership
    # höhere Ordner:   DeleteSubdirectoriesAndFiles, Delete, ChangePermissions, TakeOwnership (Umbenennen/Ersetzen des Pfads)
    # "Ordner erstellen" (4) auf Ordnern ist unkritisch, z. B. für Authenticated Users auf C:\.
    $masks = @(
        (2 -bor 4 -bor 65536 -bor 262144 -bor 524288)
        (2 -bor 64 -bor 65536 -bor 262144 -bor 524288)
    )
    $upperMask = 64 -bor 65536 -bor 262144 -bor 524288
    $reasons = @()
    $item = [Environment]::ExpandEnvironmentVariables($Path)
    $level = 0
    while ($item) {
        $mask = if ($level -lt $masks.Count) { $masks[$level] } else { $upperMask }
        # Die Laufwerkswurzel lässt sich weder löschen noch umbenennen: Delete (65536) dort ist ohne Bedeutung.
        # Sandbox-Image: Authentifizierte Benutzer haben Modify auf C:\ (nur dieser Ordner), Messung 2026-10-02.
        if (-not (Split-Path -Path $item -Parent)) { $mask = $mask -band (-bnot 65536) }
        if (Test-Path -LiteralPath $item) {
            try {
                $acl = Get-Acl -LiteralPath $item
                $ownerSid = try { ([Security.Principal.NTAccount]$acl.Owner).Translate([Security.Principal.SecurityIdentifier]).Value } catch { $null }
                if ($ownerSid -and $EdepTrustedWriterSids -notcontains $ownerSid) {
                    $reasons += Get-EdepText 'acl.owner' @($item, $acl.Owner)
                }
                foreach ($ace in $acl.Access) {
                    if ($ace.AccessControlType -ne 'Allow') { continue }
                    if ($ace.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) { continue }
                    if (([int]$ace.FileSystemRights -band $mask) -eq 0) { continue }
                    $sid = try { $ace.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value } catch { $null }
                    if ($sid -and $EdepTrustedWriterSids -notcontains $sid) {
                        $reasons += Get-EdepText 'acl.writable' @($item, $ace.IdentityReference)
                    }
                }
            }
            # Nicht lesbar ist nicht unsicher (z. B. WindowsApps ohne Adminrechte): gesondert markieren.
            catch { $reasons += $EdepAclUnknownMarker + (Get-EdepText 'acl.unreadable' @($item)) }
        }
        $parent = Split-Path -Path $item -Parent
        if (-not $parent -or $parent -eq $item) { break }
        $item = $parent
        $level++
    }
    $reasons | Select-Object -Unique
}

function Test-EdepRuleUnrestricted($Rule) {
    # EDEP-NET-03: Eine aktive ausgehende Erlaubnisregel ohne jede Einschränkung hebt die Standardsperre auf.
    # Messung 2026-10-02: Die Regel "Container: allow outbound" des Sandbox-Images (Programm, Dienst, Paket, Besitzer,
    # Protokoll, Port und Adresse alle "Any") ließ ein unbekanntes Programm trotz "ausgehend Block" hinaus.
    # $Rule ist ein flaches Objekt, damit sich die Logik ohne Firewall testen lässt.
    # Store-App-Regeln sehen im Anwendungsfilter ebenfalls uneingeschränkt aus, tragen aber PackageFamilyName/Owner.
    $open = { param($v) $t = ([string]$v).Trim(); ($t -eq '') -or ($t -eq 'Any') }
    (& $open $Rule.Program) -and (& $open $Rule.Service) -and (& $open $Rule.Package) -and
    (& $open $Rule.PackageFamilyName) -and (& $open $Rule.PolicyAppId) -and (& $open $Rule.Owner) -and
    (& $open $Rule.LocalUser) -and (& $open $Rule.RemotePort) -and (& $open $Rule.RemoteAddress) -and
    (([string]$Rule.Protocol).Trim() -in 'Any', 'TCP', '')
}

function Get-EdepUnrestrictedOutboundAllowRule {
    foreach ($r in @(Get-NetFirewallRule -PolicyStore ActiveStore -Direction Outbound -Action Allow -Enabled True -ErrorAction SilentlyContinue)) {
        $a = $r | Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue
        $p = $r | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue
        $s = $r | Get-NetFirewallServiceFilter -ErrorAction SilentlyContinue
        $d = $r | Get-NetFirewallAddressFilter -ErrorAction SilentlyContinue
        $u = $r | Get-NetFirewallSecurityFilter -ErrorAction SilentlyContinue
        $flat = [pscustomobject]@{
            Program           = [string]$a.Program
            Package           = [string]$a.Package
            PackageFamilyName = [string]$r.PackageFamilyName
            PolicyAppId       = [string]$r.PolicyAppId
            Owner             = [string]$r.Owner
            LocalUser         = [string]$u.LocalUser
            Service           = [string]$s.Service
            Protocol          = [string]$p.Protocol
            RemotePort        = ($p.RemotePort -join ',')
            RemoteAddress     = ($d.RemoteAddress -join ',')
        }
        if (Test-EdepRuleUnrestricted $flat) { $r.DisplayName }
    }
}

function ConvertTo-EdepComparablePath([string]$Path) {
    if (-not $Path) { return '' }
    [Environment]::ExpandEnvironmentVariables($Path).ToLowerInvariant()
}

# Name der App-Control-Richtlinie, die Install-EdepL1 anlegt (EDEP-ID-01).
$script:EdepAppControlPolicyName = 'EDEP L1 Audit'

function Get-EdepAppControlPolicyId {
    # IDs aller aktiven App-Control-Richtlinien mit dem Namen $Name (CiTool --list-policies -json).
    # $Json ist für Tests austauschbar; ohne Angabe wird CiTool befragt. Nicht lesbar: leere Liste.
    param([string]$Json, [string]$Name = $script:EdepAppControlPolicyName)
    try {
        if (-not $Json) { $Json = (Invoke-EdepNative { CiTool.exe --list-policies -json }) -join "`n" }
        $list = $Json | ConvertFrom-Json
        @($list.Policies | Where-Object { $_.FriendlyName -eq $Name } | ForEach-Object { [string]$_.PolicyID })
    }
    catch { @() }
}

function Test-EdepUpdateReachable {
    # Fragt die Windows-Update-Schnittstelle (wuauserv) ab. Ein Fehler ist ein sicherer Befund (die Verbindung
    # kommt nicht zustande). Ein Erfolg ist es nicht: Die Suche kann aus dem Zwischenspeicher stammen
    # (Lauf 1, Abweichung 16). $Search ist für Tests austauschbar.
    param([scriptblock]$Search = { (New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher().Search("IsInstalled=0 and Type='Software'") | Out-Null })
    try { & $Search; [pscustomobject]@{ Ok = $true; HResult = '' } }
    catch {
        $code = if ($_.Exception.HResult) { '0x{0:X8}' -f $_.Exception.HResult } else { $_.Exception.Message }
        [pscustomobject]@{ Ok = $false; HResult = $code }
    }
}

function Get-EdepUpdateProbeOutcome {
    # EDEP-TEL-04, Wirkung: ohne Messung WARN, Messung fehlgeschlagen FAIL, Messung gelungen WARN
    # (ein Erfolg beweist wegen des Zwischenspeichers keine dauerhafte Erreichbarkeit).
    param([bool]$Probed, $Probe)
    if (-not $Probed) { return [pscustomobject]@{ Status = 'WARN'; Key = 'tel04.noprobe'; Arguments = @() } }
    if ($Probe.Ok) { return [pscustomobject]@{ Status = 'WARN'; Key = 'tel04.probeok'; Arguments = @() } }
    [pscustomobject]@{ Status = 'FAIL'; Key = 'tel04.probefail'; Arguments = @($Probe.HResult) }
}

# EDEP-TEL-04: Freigabe der Update-Ziele nach Domainnamen (Lauf 2, Abweichung 6 und Lösungsversuch).
# Dienstregeln greifen für wuauserv und BITS nicht, weil sie unter dem Token des Aufrufers ohne Dienst-SID
# verbinden (E-84). Stattdessen: Programm svchost.exe, TCP 80/443, nur zu diesen Domains (Dynamic Keywords der
# Windows-Firewall, setzt den Netzwerkschutz von Defender voraus, E-88).
# Quelle der Liste (Stand 2026-10-03): Microsoft Learn, "Configure your network" (Windows Autopatch). Eine Liste
# für Unternehmensnetze, ihre Vollständigkeit für jedes System ist nicht belegt; Änderungen hier immer mit
# Quelle und Datum eintragen.
$script:EdepUpdateDomainSource = 'https://learn.microsoft.com/en-us/windows/deployment/windows-autopatch/prepare/windows-autopatch-configure-network'
$script:EdepUpdateDomainDate = '2026-10-03'
$script:EdepUpdateDomains = @(
    '*.update.microsoft.com'
    '*.windowsupdate.com'
    '*.windowsupdate.microsoft.com'
    '*.delivery.mp.microsoft.com'
    '*.dl.delivery.mp.microsoft.com'
    '*.prod.do.dsp.mp.microsoft.com'
    '*.download.microsoft.com'
    'emdl.ws.microsoft.com'
    'tsfe.trafficshaping.dsp.mp.microsoft.com'
)
$script:EdepUpdateRulePrefix = 'EDEP L1 - Update-Domain '

# Mindestgröße des Firewall-Protokolls in KB (BSI SiSyPHuS AP10, Abschnitt 4.2: "16.384 KB oder größer").
$script:EdepFirewallLogMinKb = 16384

function Invoke-EdepFlushRegistry {
    # Schreibt die Registrierungs-Hives und das Dateisystem auf den Datenträger. Hintergrund (E-76): Nach einem harten
    # Neustart direkt nach Restore-EdepL1 kam der Telemetrie-Richtlinienwert zurück (3 von 6 harten Neustarts ohne,
    # 0 von 6 mit dieser Funktion). SECURITY und SAM sind nur mit SYSTEM-Rechten schreibbar und gelten deshalb als
    # optional: Eine Absage erzeugt keine Warnung (Skipped statt Failed).
    $flushed = @(); $failed = @(); $skipped = @()
    foreach ($name in 'SOFTWARE', 'SYSTEM', 'SECURITY', 'SAM') {
        $optional = $name -in 'SECURITY', 'SAM'
        try {
            $k = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($name)
            if ($k) { $k.Flush(); $k.Close(); $flushed += $name }
            elseif ($optional) { $skipped += $name }
        }
        catch { if ($optional) { $skipped += $name } else { $failed += $name } }
    }
    try { [Microsoft.Win32.Registry]::LocalMachine.Flush(); $flushed += 'HKLM' }
    catch { $failed += 'HKLM' }
    try { Write-VolumeCache -DriveLetter $env:SystemDrive.Substring(0, 1) -ErrorAction Stop; $flushed += 'Datenträger' }
    catch { $failed += 'Datenträger' }
    [pscustomobject]@{ Flushed = $flushed; Failed = $failed; Skipped = $skipped }
}

function Get-EdepSmallLogProfile {
    # Namen der Profile, deren Firewall-Protokoll kleiner als das empfohlene Mindestmaß ist.
    param($Profiles, [int]$MinKb = $script:EdepFirewallLogMinKb)
    @($Profiles | Where-Object { [int64]$_.LogMaxSizeKilobytes -lt $MinKb } | ForEach-Object { [string]$_.Name })
}

function Get-EdepNetworkProtectionName {
    # EnableNetworkProtection: 0 aus, 1 an (Block), 2 Audit. Für Set-MpPreference.
    param([int]$Value)
    switch ($Value) { 0 { 'Disabled' } 1 { 'Enabled' } 2 { 'AuditMode' } default { throw "Unbekannter Wert für den Netzwerkschutz: $Value" } }
}

function Get-EdepNetworkProtection {
    # Aktueller Wert des Netzwerkschutzes oder $null, wenn Defender ihn nicht liefert (z. B. fremder Virenschutz).
    try { [int](Get-MpPreference -ErrorAction Stop).EnableNetworkProtection } catch { $null }
}

function Select-EdepUpdateKeyword {
    # Wählt aus Dynamic-Keyword-Objekten die von EDEP angelegten (AutoResolve und Domain aus der Liste).
    param($Keyword)
    @($Keyword | Where-Object { $_.AutoResolve -and ($script:EdepUpdateDomains -contains $_.Keyword) })
}

function Get-EdepUpdateDomainStatus {
    # TEL-04 unter "ausgehend Block": ok | nodomains (keine Regeln) | nonp (Netzwerkschutz aus oder nicht verfügbar)
    param([int]$RuleCount, $NetworkProtection)
    if ($RuleCount -eq 0) { return 'nodomains' }
    if ($null -eq $NetworkProtection -or $NetworkProtection -notin 1, 2) { return 'nonp' }
    'ok'
}

function Get-EdepNetworkProtectionRestoreValue {
    # Wert, auf den der Netzwerkschutz zurückgestellt wird: der Wert VOR der ersten Änderung durch EDEP, also der Eintrag
    # der ältesten Sicherung, die "networkProtectionChanged" trägt. Keine solche Sicherung: $null (nichts zurückstellen).
    # $Manifest: Manifeste in der Reihenfolge der Sicherungen (älteste zuerst).
    param($Manifest)
    $first = @($Manifest | Where-Object { $_.networkProtectionChanged } | Select-Object -First 1)
    if ($first.Count -eq 0 -or $null -eq $first[0].networkProtection) { return $null }
    [int]$first[0].networkProtection
}

function Remove-EdepUpdateKeyword {
    # Entfernt die von EDEP angelegten Schlüsselwörter (die Firewall-Sicherung enthält sie nicht).
    if (-not (Get-Command Get-NetFirewallDynamicKeywordAddress -ErrorAction SilentlyContinue)) { return }
    foreach ($k in Select-EdepUpdateKeyword (Get-NetFirewallDynamicKeywordAddress -AllAutoResolve -ErrorAction SilentlyContinue)) {
        Remove-NetFirewallDynamicKeywordAddress -Id $k.Id -ErrorAction SilentlyContinue
    }
}

function Get-EdepEditionSupportsSecurityTelemetry {
    # AllowTelemetry=0 wirkt nur auf Enterprise, Education, IoT Enterprise und Server.
    $edition = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction SilentlyContinue).EditionID
    [pscustomobject]@{
        EditionId = $edition
        Supported = [bool]($edition -match 'Enterprise|Education|Server')
    }
}
