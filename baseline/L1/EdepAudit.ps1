# EDEP-Audit: bewertet, wie offen ein Windows-System für Datenabfluss und Angriffe ist.
# Setzt EdepStrings.ps1, EdepL1.Common.ps1 und EdepL1.Checks.ps1 voraus. Ändert nichts am System.

# ---------------------------------------------------------------------------
# Katalog: Kategorie, Gewicht sowie Titel, Begründung und Empfehlung je Sprache.
# Gewicht 0 = wird angezeigt, geht aber nicht in die Punktzahl ein.
# ---------------------------------------------------------------------------
$script:EdepAuditCatalog = [ordered]@{
    'EDEP-NET-03' = @{ Category = 'cat.out'; Weight = 10
        de = @{ Title = 'Ausgehender Verkehr standardmäßig blockiert'
                Why   = 'Ist ausgehender Verkehr standardmäßig erlaubt, kann jedes Programm, auch Schadcode, ungehindert Daten senden und Befehle nachladen. Windows lässt ausgehend standardmäßig alles zu, auch mit Defender.'
                Fix   = 'Ausgehende Standardaktion auf Block setzen und nur benötigte Programme freigeben (Install-EdepL1.ps1 -Enforce -AllowProgram ...). Vorher im Audit-Modus das Firewall-Log auswerten.' }
        en = @{ Title = 'Outbound traffic blocked by default'
                Why   = 'If outbound traffic is allowed by default, every program, including malware, can send data and download payloads unhindered. Windows allows all outbound traffic by default, even with Defender.'
                Fix   = 'Set the default outbound action to Block and allow only required programs (Install-EdepL1.ps1 -Enforce -AllowProgram ...). Review the firewall log in audit mode first.' } }
    'EDEP-NET-04' = @{ Category = 'cat.out'; Weight = 8
        de = @{ Title = 'Windows-Bordwerkzeuge (LOLBins) ausgehend gesperrt'
                Why   = 'Angreifer laden Schadcode bevorzugt mit Bordwerkzeugen wie PowerShell, curl, certutil oder mshta nach, weil diese signiert und überall vorhanden sind.'
                Fix   = 'Ausgehende Blockregeln für die Programme aus SPEC.md Anhang A anlegen (Install-EdepL1.ps1 erledigt das auch im Audit-Modus).' }
        en = @{ Title = 'Built-in Windows tools (LOLBins) blocked outbound'
                Why   = 'Attackers prefer built-in tools such as PowerShell, curl, certutil or mshta to download payloads because they are signed and present everywhere.'
                Fix   = 'Create outbound block rules for the programs in SPEC.md Annex A (Install-EdepL1.ps1 does this even in audit mode).' } }
    'EDEP-NET-10' = @{ Category = 'cat.out'; Weight = 6
        de = @{ Title = 'Freigegebene Programme nur durch Admins änderbar'
                Why   = 'Liegt ein Programm mit Netzfreigabe in einem Ordner, den der Benutzer beschreiben darf (z. B. AppData), kann Schadcode die Datei austauschen oder eine DLL daneben legen und erbt die Freigabe.'
                Fix   = 'Programme systemweit unter C:\Program Files installieren oder die Freigabe entfernen. In EDEP L2 wird die Freigabe zusätzlich an Signatur oder Hash gebunden.' }
        en = @{ Title = 'Allowed programs modifiable by admins only'
                Why   = 'If a program with network access lives in a folder the user can write to (e.g. AppData), malware can replace the file or plant a DLL next to it and inherit the permission.'
                Fix   = 'Install programs system-wide under C:\Program Files or remove the permission. EDEP L2 additionally binds permissions to signature or hash.' } }
    'AUD-NETPROT' = @{ Category = 'cat.out'; Weight = 4
        de = @{ Title = 'Defender Network Protection aktiv'
                Why   = 'Network Protection blockiert Verbindungen zu bekannten Schad- und Phishing-Zielen für alle Programme, nicht nur im Browser.'
                Fix   = 'Set-MpPreference -EnableNetworkProtection Enabled' }
        en = @{ Title = 'Defender Network Protection enabled'
                Why   = 'Network Protection blocks connections to known malicious and phishing destinations for all programs, not only in the browser.'
                Fix   = 'Set-MpPreference -EnableNetworkProtection Enabled' } }
    'EDEP-NET-01' = @{ Category = 'cat.in'; Weight = 8
        de = @{ Title = 'Firewall aktiv, eingehend blockiert'
                Why   = 'Ohne aktive Firewall sind alle lauschenden Dienste aus dem Netz erreichbar.'
                Fix   = 'Firewall in allen Profilen aktivieren, eingehende Standardaktion Block.' }
        en = @{ Title = 'Firewall enabled, inbound blocked'
                Why   = 'Without an active firewall, every listening service is reachable from the network.'
                Fix   = 'Enable the firewall in all profiles with default inbound action Block.' } }
    'EDEP-NET-02' = @{ Category = 'cat.in'; Weight = 3
        de = @{ Title = 'Stealth-Modus aktiv'
                Why   = 'Im Stealth-Modus antwortet der Rechner nicht auf Anfragen an geschlossene Ports und ist für Scanner schwerer zu erkennen.'
                Fix   = 'Registrierungswert DisableStealthMode entfernen oder auf 0 setzen.' }
        en = @{ Title = 'Stealth mode active'
                Why   = 'In stealth mode the computer does not answer requests to closed ports and is harder for scanners to detect.'
                Fix   = 'Remove the registry value DisableStealthMode or set it to 0.' } }
    'EDEP-NET-05' = @{ Category = 'cat.in'; Weight = 5
        de = @{ Title = 'SMB/RDP/WinRM/RPC in öffentlichen Netzen gesperrt'
                Why   = 'In Hotel-, Bahn- oder Café-WLANs sind Datei- und Fernwartungsdienste ein häufiger Einstiegspunkt.'
                Fix   = 'Eingehende Blockregel im Profil Public für TCP 135, 445, 3389, 5985, 5986.' }
        en = @{ Title = 'SMB/RDP/WinRM/RPC blocked on public networks'
                Why   = 'On hotel, train or café Wi-Fi, file sharing and remote management services are a common entry point.'
                Fix   = 'Inbound block rule in the Public profile for TCP 135, 445, 3389, 5985, 5986.' } }
    'EDEP-ID-01' = @{ Category = 'cat.prog'; Weight = 6
        de = @{ Title = 'App Control for Business aktiv'
                Why   = 'App Control legt fest, welcher Code überhaupt starten darf, und wird vom Windows-Kernel durchgesetzt.'
                Fix   = 'Mit der Richtlinie DefaultWindows_Audit im Audit-Modus beginnen (Install-EdepL1.ps1 -DeployAppControlAudit), Protokolle auswerten, dann erzwingen.' }
        en = @{ Title = 'App Control for Business active'
                Why   = 'App Control defines which code may run at all and is enforced by the Windows kernel.'
                Fix   = 'Start with the DefaultWindows_Audit policy in audit mode (Install-EdepL1.ps1 -DeployAppControlAudit), review the logs, then enforce.' } }
    'AUD-ASR' = @{ Category = 'cat.prog'; Weight = 3
        de = @{ Title = 'Defender-ASR-Regeln im Blockiermodus'
                Why   = 'Attack-Surface-Reduction-Regeln stoppen typische Angriffsketten, z. B. Office-Makros, die Prozesse starten.'
                Fix   = 'ASR-Regeln zunächst im Audit-, dann im Blockiermodus aktivieren (Add-MpPreference -AttackSurfaceReductionRules_Ids ...).' }
        en = @{ Title = 'Defender ASR rules in block mode'
                Why   = 'Attack surface reduction rules stop typical attack chains, e.g. Office macros launching processes.'
                Fix   = 'Enable ASR rules in audit mode first, then in block mode (Add-MpPreference -AttackSurfaceReductionRules_Ids ...).' } }
    'EDEP-TEL-01' = @{ Category = 'cat.tel'; Weight = 3
        de = @{ Title = 'Telemetrie auf niedrigster Stufe'
                Why   = 'Ohne Richtlinie können optionale Diagnosedaten übertragen werden.'
                Fix   = 'Richtlinie AllowTelemetry auf 0 setzen (wirkt auf Home/Pro als 1 = Required).' }
        en = @{ Title = 'Telemetry at the lowest level'
                Why   = 'Without a policy, optional diagnostic data may be sent.'
                Fix   = 'Set the AllowTelemetry policy to 0 (acts as 1 = Required on Home/Pro).' } }
    'EDEP-TEL-02' = @{ Category = 'cat.tel'; Weight = 4
        de = @{ Title = 'Telemetrie-Dienste ausgehend gesperrt'
                Why   = 'DiagTrack und dmwappushservice übertragen Diagnose- und Nutzungsdaten an Microsoft.'
                Fix   = 'Ausgehende Blockregeln auf Dienstebene (nicht per IP- oder Hosts-Liste, das bricht Updates).' }
        en = @{ Title = 'Telemetry services blocked outbound'
                Why   = 'DiagTrack and dmwappushservice send diagnostic and usage data to Microsoft.'
                Fix   = 'Outbound block rules at service level (not via IP or hosts lists, which break updates).' } }
    'EDEP-TEL-03' = @{ Category = 'cat.tel'; Weight = 2
        de = @{ Title = 'Werbe-ID und Aktivitätsverlauf deaktiviert'
                Why   = 'Werbe-ID und Aktivitätsverlauf ermöglichen Profilbildung. Microsoft empfiehlt selbst, den Verlauf abzuschalten, nicht nur seinen Upload.'
                Fix   = 'Richtlinien AdvertisingInfo\DisabledByGroupPolicy=1 sowie System\EnableActivityFeed=0, PublishUserActivities=0, UploadUserActivities=0.' }
        en = @{ Title = 'Advertising ID and activity history disabled'
                Why   = 'The advertising ID and activity history enable profiling. Microsoft itself recommends turning off the history, not just its upload.'
                Fix   = 'Policies AdvertisingInfo\DisabledByGroupPolicy=1 and System\EnableActivityFeed=0, PublishUserActivities=0, UploadUserActivities=0.' } }
    'EDEP-TEL-04' = @{ Category = 'cat.tel'; Weight = 5
        de = @{ Title = 'Sicherheitsupdates erreichbar'
                Why   = 'Wer beim Abschotten Windows Update, Defender-Signaturen oder Zertifikatsprüfungen blockiert, macht das System unsicherer.'
                Fix   = 'Dienste wuauserv, BITS, DoSvc, CryptSvc, W32Time und Defender ausgehend erlauben.' }
        en = @{ Title = 'Security updates reachable'
                Why   = 'Blocking Windows Update, Defender signatures or certificate checks while locking down makes the system less secure.'
                Fix   = 'Allow the services wuauserv, BITS, DoSvc, CryptSvc, W32Time and Defender outbound.' } }
    'EDEP-LOG-01' = @{ Category = 'cat.log'; Weight = 4
        de = @{ Title = 'Blockierte Verbindungen werden protokolliert'
                Why   = 'Ohne Protokoll bleibt unbemerkt, welche Programme wohin senden wollten.'
                Fix   = 'Firewall-Log für verworfene Pakete und Überwachung „Filterplattformverbindung“ (Ereignis 5157) aktivieren.' }
        en = @{ Title = 'Blocked connections are logged'
                Why   = 'Without a log, it goes unnoticed which programs tried to send data where.'
                Fix   = 'Enable the firewall log for dropped packets and the audit subcategory "Filtering Platform Connection" (event 5157).' } }
    'EDEP-LOG-02' = @{ Category = 'cat.log'; Weight = 2
        de = @{ Title = 'Firewall-Log bleibt lokal'
                Why   = 'Protokolle sollen nur mit ausdrücklicher Entscheidung das Gerät verlassen.'
                Fix   = 'LogFileName auf einen lokalen Pfad setzen.' }
        en = @{ Title = 'Firewall log stays local'
                Why   = 'Logs should leave the device only by explicit decision.'
                Fix   = 'Set LogFileName to a local path.' } }
    'EDEP-LOG-06' = @{ Category = 'cat.log'; Weight = 3
        de = @{ Title = 'BITS-Übertragungen werden protokolliert'
                Why   = 'Über den Windows-Dienst BITS kann jeder Benutzer Dateien laden und hochladen, auch wenn Programme sonst gesperrt sind (MITRE ATT&CK T1197). Das Protokoll ist das Erkennungsmittel.'
                Fix   = 'Protokoll Microsoft-Windows-Bits-Client/Operational aktivieren (wevtutil sl Microsoft-Windows-Bits-Client/Operational /e:true).' }
        en = @{ Title = 'BITS transfers are logged'
                Why   = 'Through the Windows BITS service any user can download and upload files even when programs are otherwise blocked (MITRE ATT&CK T1197). The log is the means of detection.'
                Fix   = 'Enable the log Microsoft-Windows-Bits-Client/Operational (wevtutil sl Microsoft-Windows-Bits-Client/Operational /e:true).' } }
    'AUD-PSLOG' = @{ Category = 'cat.log'; Weight = 2
        de = @{ Title = 'PowerShell-Skriptblockprotokollierung aktiv'
                Why   = 'Ohne Skriptblockprotokoll ist nicht nachvollziehbar, welcher PowerShell-Code ausgeführt wurde.'
                Fix   = 'Richtlinie „PowerShell-Skriptblockprotokollierung aktivieren“ (ScriptBlockLogging\EnableScriptBlockLogging = 1).' }
        en = @{ Title = 'PowerShell script block logging enabled'
                Why   = 'Without script block logging it cannot be traced which PowerShell code was executed.'
                Fix   = 'Policy "Turn on PowerShell Script Block Logging" (ScriptBlockLogging\EnableScriptBlockLogging = 1).' } }
    'AUD-SMB1' = @{ Category = 'cat.surface'; Weight = 5
        de = @{ Title = 'SMBv1-Client nicht aktiv'
                Why   = 'SMBv1 ist veraltet und war Einfallstor von WannaCry und NotPetya.'
                Fix   = 'Windows-Feature „SMB 1.0/CIFS-Dateifreigabeunterstützung“ entfernen.' }
        en = @{ Title = 'SMBv1 client not active'
                Why   = 'SMBv1 is obsolete and was the entry point for WannaCry and NotPetya.'
                Fix   = 'Remove the Windows feature "SMB 1.0/CIFS File Sharing Support".' } }
    'AUD-RDP' = @{ Category = 'cat.surface'; Weight = 4
        de = @{ Title = 'Remotedesktop aus oder mit NLA'
                Why   = 'Offenes RDP ist einer der häufigsten Einstiegspunkte für Ransomware. Ohne Netzwerkebenen-Authentifizierung (NLA) ist der Anmeldebildschirm ungeschützt erreichbar.'
                Fix   = 'Remotedesktop deaktivieren oder zumindest NLA erzwingen und nur über VPN erreichbar machen.' }
        en = @{ Title = 'Remote Desktop off or with NLA'
                Why   = 'Exposed RDP is one of the most common ransomware entry points. Without Network Level Authentication (NLA) the logon screen is reachable unprotected.'
                Fix   = 'Disable Remote Desktop or at least enforce NLA and make it reachable only via VPN.' } }
    'AUD-LLMNR' = @{ Category = 'cat.surface'; Weight = 3
        de = @{ Title = 'LLMNR deaktiviert'
                Why   = 'Über LLMNR-Antworten kann ein Angreifer im selben Netz Namensauflösungen fälschen und Anmelde-Hashes abgreifen.'
                Fix   = 'Richtlinie „Multicastnamensauflösung deaktivieren“ (DNSClient\EnableMulticast = 0).' }
        en = @{ Title = 'LLMNR disabled'
                Why   = 'Through LLMNR responses an attacker on the same network can spoof name resolution and capture logon hashes.'
                Fix   = 'Policy "Turn off multicast name resolution" (DNSClient\EnableMulticast = 0).' } }
    'AUD-PSV2' = @{ Category = 'cat.surface'; Weight = 3
        de = @{ Title = 'PowerShell 2.0 entfernt'
                Why   = 'Mit „powershell -Version 2“ umgehen Angreifer Skriptprotokollierung und AMSI.'
                Fix   = 'Windows-Feature „Windows PowerShell 2.0“ entfernen.' }
        en = @{ Title = 'PowerShell 2.0 removed'
                Why   = 'With "powershell -Version 2" attackers bypass script logging and AMSI.'
                Fix   = 'Remove the Windows feature "Windows PowerShell 2.0".' } }
    'AUD-NETBIOS' = @{ Category = 'cat.surface'; Weight = 2
        de = @{ Title = 'NetBIOS über TCP/IP deaktiviert'
                Why   = 'NetBIOS-Namensdienst ermöglicht denselben Angriff wie LLMNR und verrät Rechner- und Benutzernamen.'
                Fix   = 'Pro Netzwerkadapter NetBIOS über TCP/IP deaktivieren (NetbiosOptions = 2).' }
        en = @{ Title = 'NetBIOS over TCP/IP disabled'
                Why   = 'The NetBIOS name service enables the same attack as LLMNR and reveals computer and user names.'
                Fix   = 'Disable NetBIOS over TCP/IP per network adapter (NetbiosOptions = 2).' } }
    'AUD-LISTEN' = @{ Category = 'cat.surface'; Weight = 0
        de = @{ Title = 'Aus dem Netz erreichbare Dienste'
                Why   = 'Jeder Prozess, der auf einer Nicht-Loopback-Adresse lauscht, ist potenziell von außen erreichbar, sofern die Firewall es zulässt.'
                Fix   = 'Nicht benötigte Dienste beenden; benötigte nur im Profil Domain/Private freigeben.' }
        en = @{ Title = 'Services reachable from the network'
                Why   = 'Every process listening on a non-loopback address is potentially reachable from outside if the firewall allows it.'
                Fix   = 'Stop unneeded services; allow needed ones only in the Domain/Private profile.' } }
    'EDEP-OPS-01' = @{ Category = 'cat.ops'; Weight = 0
        de = @{ Title = 'EDEP-Sicherung vorhanden'
                Why   = 'Nur relevant, wenn EDEP angewendet wurde: Ohne Sicherung gibt es keinen sauberen Rückweg.'
                Fix   = 'Install-EdepL1.ps1 legt vor jeder Änderung eine Sicherung an.' }
        en = @{ Title = 'EDEP backup present'
                Why   = 'Only relevant if EDEP was applied: without a backup there is no clean way back.'
                Fix   = 'Install-EdepL1.ps1 creates a backup before every change.' } }
}

function Get-EdepAuditExtraResult {
    [CmdletBinding()]
    param([bool]$IsAdmin)

    $results = [System.Collections.Generic.List[object]]::new()
    function Add-Result([string]$Id, [string]$Status, [string]$Key, [object[]]$Arguments = @()) {
        $results.Add([pscustomobject]@{ Id = $Id; Status = $Status; Detail = (Get-EdepText $Key $Arguments) })
    }

    # --- SMBv1 ---------------------------------------------------------------
    $smb1 = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10' -ErrorAction SilentlyContinue
    if (-not $smb1) { Add-Result 'AUD-SMB1' 'PASS' 'smb1.pass' }
    elseif ($smb1.Start -eq 4) { Add-Result 'AUD-SMB1' 'WARN' 'smb1.warn' }
    else { Add-Result 'AUD-SMB1' 'FAIL' 'smb1.fail' @($smb1.Start) }

    # --- LLMNR ---------------------------------------------------------------
    $llmnr = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name EnableMulticast -ErrorAction SilentlyContinue
    if ($llmnr -and $llmnr.EnableMulticast -eq 0) { Add-Result 'AUD-LLMNR' 'PASS' 'llmnr.pass' }
    else { Add-Result 'AUD-LLMNR' 'FAIL' 'llmnr.fail' }

    # --- NetBIOS über TCP/IP ---------------------------------------------------
    $ifaces = @(Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces' -ErrorAction SilentlyContinue |
        ForEach-Object { (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).NetbiosOptions })
    $enabled = @($ifaces | Where-Object { $_ -ne 2 }).Count
    if ($ifaces.Count -eq 0) { Add-Result 'AUD-NETBIOS' 'UNKNOWN' 'netbios.unknown' }
    elseif ($enabled -eq 0) { Add-Result 'AUD-NETBIOS' 'PASS' 'netbios.pass' @($ifaces.Count) }
    else { Add-Result 'AUD-NETBIOS' 'FAIL' 'netbios.fail' @($enabled, $ifaces.Count) }

    # --- RDP -----------------------------------------------------------------
    $ts = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -ErrorAction SilentlyContinue
    if ($ts -and $ts.fDenyTSConnections -eq 1) { Add-Result 'AUD-RDP' 'PASS' 'rdp.pass' }
    else {
        $nla = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication -ErrorAction SilentlyContinue
        if ($nla -and $nla.UserAuthentication -eq 1) { Add-Result 'AUD-RDP' 'WARN' 'rdp.warn' }
        else { Add-Result 'AUD-RDP' 'FAIL' 'rdp.fail' }
    }

    # --- PowerShell 2.0 --------------------------------------------------------
    $ps2 = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine' -ErrorAction SilentlyContinue
    if ($ps2 -and $ps2.PowerShellVersion -like '2.*') { Add-Result 'AUD-PSV2' 'FAIL' 'psv2.fail' }
    else { Add-Result 'AUD-PSV2' 'PASS' 'psv2.pass' }

    # --- Defender: Network Protection und ASR (nur mit Adminrechten sichtbar) ---
    $mp = $null
    $mpStatus = $null
    if ($IsAdmin) {
        $mp = Get-MpPreference -ErrorAction SilentlyContinue
        $mpStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
    }
    if (-not $IsAdmin) {
        Add-Result 'AUD-NETPROT' 'UNKNOWN' 'def.noadmin'
        Add-Result 'AUD-ASR' 'UNKNOWN' 'def.noadmin'
    }
    elseif (-not $mp -or ($mpStatus -and -not $mpStatus.AntivirusEnabled)) {
        Add-Result 'AUD-NETPROT' 'UNKNOWN' 'def.notactive'
        Add-Result 'AUD-ASR' 'UNKNOWN' 'def.notactive'
    }
    else {
        switch ([int]$mp.EnableNetworkProtection) {
            1 { Add-Result 'AUD-NETPROT' 'PASS' 'np.pass' }
            2 { Add-Result 'AUD-NETPROT' 'WARN' 'np.warn' }
            default { Add-Result 'AUD-NETPROT' 'FAIL' 'np.fail' }
        }
        $actions = @($mp.AttackSurfaceReductionRules_Actions | ForEach-Object { [int]$_ })
        $block = @($actions | Where-Object { $_ -eq 1 }).Count
        $audit = @($actions | Where-Object { $_ -in 2, 6 }).Count
        if ($block -gt 0) { Add-Result 'AUD-ASR' 'PASS' 'asr.pass' @($block, $audit) }
        elseif ($audit -gt 0) { Add-Result 'AUD-ASR' 'WARN' 'asr.warn' @($audit) }
        else { Add-Result 'AUD-ASR' 'FAIL' 'asr.fail' }
    }

    # --- PowerShell-Skriptblockprotokollierung --------------------------------
    $sbl = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name EnableScriptBlockLogging -ErrorAction SilentlyContinue
    if ($sbl -and $sbl.EnableScriptBlockLogging -eq 1) { Add-Result 'AUD-PSLOG' 'PASS' 'pslog.pass' }
    else { Add-Result 'AUD-PSLOG' 'FAIL' 'pslog.fail' }

    # --- Lauschende Dienste (informativ) --------------------------------------
    $listen = @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
        Where-Object { $_.LocalAddress -notmatch '^(127\.|::1$)' })
    if ($listen.Count -eq 0) { Add-Result 'AUD-LISTEN' 'INFO' 'listen.none' }
    else {
        $byProc = $listen | Group-Object OwningProcess | ForEach-Object {
            $name = (Get-Process -Id ([int]$_.Name) -ErrorAction SilentlyContinue).ProcessName
            if (-not $name) { $name = "PID $($_.Name)" }
            $ports = ($_.Group.LocalPort | Sort-Object -Unique) -join ','
            "$name ($ports)"
        }
        Add-Result 'AUD-LISTEN' 'INFO' 'listen.some' @($listen.Count, (($byProc | Sort-Object) -join '; '))
    }

    $results
}

function Get-EdepAuditScore($Findings) {
    $scored = @($Findings | Where-Object { $_.Weight -gt 0 -and $_.Status -in 'PASS', 'WARN', 'FAIL' })
    $max = ($scored | Measure-Object -Property Weight -Sum).Sum
    if (-not $max) { return [pscustomobject]@{ Score = 0; Grade = '-'; Max = 0 } }
    $got = 0.0
    foreach ($f in $scored) {
        if ($f.Status -eq 'PASS') { $got += $f.Weight }
        elseif ($f.Status -eq 'WARN') { $got += $f.Weight / 2 }
    }
    $score = [int][Math]::Round(100 * $got / $max)
    $grade = if ($score -ge 90) { 'A' } elseif ($score -ge 75) { 'B' } elseif ($score -ge 50) { 'C' } elseif ($score -ge 25) { 'D' } else { 'E' }
    [pscustomobject]@{ Score = $score; Grade = $grade; Max = $max }
}

function ConvertTo-EdepAuditHtml($Report) {
    $enc = { param($s) [System.Net.WebUtility]::HtmlEncode([string]$s) }

    $css = @'
:root{--bg:#f6f7f9;--card:#fff;--fg:#1b1f24;--muted:#5b6571;--line:#e3e6ea;
--pass:#1a7f37;--warn:#9a6700;--fail:#cf222e;--unk:#6e7781;--info:#0969da;--accent:#0969da}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){--bg:#0d1117;--card:#161b22;--fg:#e6edf3;--muted:#8d96a0;
--line:#30363d;--pass:#3fb950;--warn:#d29922;--fail:#f85149;--unk:#8d96a0;--info:#58a6ff;--accent:#58a6ff}}
:root[data-theme="dark"]{--bg:#0d1117;--card:#161b22;--fg:#e6edf3;--muted:#8d96a0;
--line:#30363d;--pass:#3fb950;--warn:#d29922;--fail:#f85149;--unk:#8d96a0;--info:#58a6ff;--accent:#58a6ff}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);
font:15px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{max-width:980px;margin:0 auto;padding:24px 16px 48px}
h1{font-size:22px;margin:0 0 4px}h2{font-size:17px;margin:32px 0 12px}
.meta{color:var(--muted);font-size:13px}
.hero{display:flex;gap:24px;align-items:center;flex-wrap:wrap;background:var(--card);border:1px solid var(--line);
border-radius:12px;padding:20px;margin-top:16px}
.score{font-size:56px;font-weight:700;line-height:1}.score small{font-size:20px;color:var(--muted);font-weight:500}
.grade{font-size:15px;font-weight:600;padding:4px 10px;border-radius:999px;border:1px solid var(--line)}
.counts{display:flex;gap:16px;flex-wrap:wrap;font-size:14px}
.cats{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px}
.cat{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px}
.bar{height:6px;background:var(--line);border-radius:3px;margin-top:8px;overflow:hidden}
.bar span{display:block;height:100%;background:var(--accent)}
.f{background:var(--card);border:1px solid var(--line);border-left-width:4px;border-radius:10px;padding:14px 16px;margin-bottom:10px}
.f.PASS{border-left-color:var(--pass)}.f.WARN{border-left-color:var(--warn)}.f.FAIL{border-left-color:var(--fail)}
.f.UNKNOWN{border-left-color:var(--unk)}.f.INFO{border-left-color:var(--info)}
.f h3{font-size:15px;margin:0;display:flex;gap:8px;align-items:baseline;flex-wrap:wrap}
.b{font-size:12px;font-weight:600;padding:1px 8px;border-radius:999px;color:#fff}
.b.PASS{background:var(--pass)}.b.WARN{background:var(--warn)}.b.FAIL{background:var(--fail)}.b.UNKNOWN{background:var(--unk)}.b.INFO{background:var(--info)}
.id{font:12px ui-monospace,Consolas,monospace;color:var(--muted)}
.d{margin:6px 0 0;word-break:break-word}.why,.fix{margin:6px 0 0;color:var(--muted);font-size:14px}
.fix b,.why b{color:var(--fg)}
.note{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px 16px;font-size:14px;color:var(--muted)}
footer{margin-top:32px;font-size:12px;color:var(--muted)}
'@

    $order = @{ FAIL = 0; WARN = 1; UNKNOWN = 2; INFO = 3; PASS = 4 }
    $admin = if ($Report.IsAdmin) { Get-EdepText 'html.admin' } else { Get-EdepText 'html.noadmin' }
    $c = $Report.Counts
    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.Append("<!doctype html><html lang=`"$($Report.Language)`"><head><meta charset=`"utf-8`">")
    [void]$sb.Append('<meta name="viewport" content="width=device-width,initial-scale=1">')
    [void]$sb.Append("<title>$(& $enc (Get-EdepText 'html.title' @($Report.Computer)))</title><style>$css</style></head><body><main>")
    [void]$sb.Append("<h1>$(& $enc (Get-EdepText 'html.title' @($Report.Computer)))</h1>")
    [void]$sb.Append("<div class=`"meta`">$(& $enc $Report.Os) · $(& $enc (Get-EdepText 'html.checked' @($Report.CheckedDisplay))) · EDEP $(& $enc $Report.Version) · $(& $enc $admin)</div>")

    [void]$sb.Append('<section class="hero">')
    [void]$sb.Append("<div class=`"score`">$($Report.Score.Score)<small>/100</small></div>")
    [void]$sb.Append("<div><div class=`"grade`">$(& $enc (Get-EdepText 'html.grade' @($Report.Score.Grade)))</div></div>")
    [void]$sb.Append('<div class="counts">')
    foreach ($s in 'FAIL', 'WARN', 'PASS', 'UNKNOWN') {
        [void]$sb.Append("<span>$(& $enc (Get-EdepText "st.$s")): <b>$($c.$s)</b></span>")
    }
    [void]$sb.Append('</div></section>')

    if (-not $Report.IsAdmin) { [void]$sb.Append("<p class=`"note`">$(& $enc (Get-EdepText 'html.note'))</p>") }

    [void]$sb.Append("<h2>$(& $enc (Get-EdepText 'html.categories'))</h2><div class=`"cats`">")
    foreach ($cat in $Report.Categories) {
        [void]$sb.Append("<div class=`"cat`"><b>$(& $enc $cat.Name)</b><div class=`"meta`">$(& $enc (Get-EdepText 'html.catline' @($cat.Score, $cat.Open)))</div><div class=`"bar`"><span style=`"width:$($cat.Score)%`"></span></div></div>")
    }
    [void]$sb.Append("</div><h2>$(& $enc (Get-EdepText 'html.findings'))</h2>")

    foreach ($f in ($Report.Findings | Sort-Object { $order[$_.Status] }, { - $_.Weight })) {
        $st = $f.Status
        [void]$sb.Append("<article class=`"f $st`"><h3><span class=`"b $st`">$(& $enc (Get-EdepText "st.$st"))</span>$(& $enc $f.Title)<span class=`"id`">$(& $enc $f.Id)</span></h3>")
        [void]$sb.Append("<p class=`"d`">$(& $enc $f.Detail)</p>")
        if ($st -ne 'PASS') {
            [void]$sb.Append("<p class=`"why`"><b>$(& $enc (Get-EdepText 'html.why'))</b> $(& $enc $f.Why)</p>")
            [void]$sb.Append("<p class=`"fix`"><b>$(& $enc (Get-EdepText 'html.fix'))</b> $(& $enc $f.Fix)</p>")
        }
        [void]$sb.Append('</article>')
    }

    [void]$sb.Append("<footer>$(& $enc (Get-EdepText 'html.footer'))</footer></main></body></html>")
    $sb.ToString()
}

function Invoke-EdepAudit {
    <#
    .SYNOPSIS
        Bewertet, wie offen dieses Windows-System für Datenabfluss und Angriffe ist. Ändert nichts.
        Rates how open this Windows system is to data exfiltration and attacks. Changes nothing.

    .DESCRIPTION
        Führt die EDEP-L1-Prüfungen und zusätzliche Prüfungen zur Angriffsfläche aus und
        berechnet eine gewichtete Punktzahl (0–100). Läuft auch ohne Adminrechte; einige
        Prüfungen sind dann "nicht prüfbar" und zählen nicht in die Punktzahl.

    .PARAMETER OutputPath
        Ordner für den HTML-Bericht. Standard: aktuelles Verzeichnis.

    .PARAMETER NoHtml
        Keinen HTML-Bericht schreiben.

    .PARAMETER Open
        HTML-Bericht nach dem Schreiben im Standardbrowser öffnen.

    .PARAMETER PassThru
        Gibt das Berichtsobjekt zurück (z. B. für ConvertTo-Json).

    .PARAMETER Language
        de oder en. Standard: Windows-Anzeigesprache (Deutsch, sonst Englisch).

    .EXAMPLE
        Invoke-EdepAudit -Open
    .EXAMPLE
        Invoke-EdepAudit -Language en -NoHtml -PassThru | ConvertTo-Json -Depth 5
    #>
    [CmdletBinding()]
    param(
        [string]$OutputPath = (Get-Location).ProviderPath,
        [switch]$NoHtml,
        [switch]$Open,
        [switch]$PassThru,
        [ValidateSet('de', 'en')][string]$Language
    )

    if ($Language) { Set-EdepLanguage $Language }
    $lang = $EdepLanguage

    $isAdmin = Test-EdepIsAdmin
    $raw = @(Get-EdepL1CheckResult) + @(Get-EdepAuditExtraResult -IsAdmin $isAdmin)

    $findings = foreach ($r in $raw) {
        $meta = $EdepAuditCatalog[$r.Id]
        if (-not $meta) { continue }
        $text = $meta[$lang]
        # EDEP-spezifische Sicherung ist für ein reines Audit ohne EDEP nicht relevant.
        $status = $r.Status
        if ($r.Id -eq 'EDEP-OPS-01' -and $status -eq 'FAIL') { $status = 'INFO' }
        [pscustomobject]@{
            Id = $r.Id; Status = $status; Detail = $r.Detail
            Title = $text.Title; Category = (Get-EdepText $meta.Category); Weight = $meta.Weight
            Why = $text.Why; Fix = $text.Fix
        }
    }

    $counts = @{}
    foreach ($s in 'PASS', 'WARN', 'FAIL', 'UNKNOWN', 'INFO') { $counts[$s] = @($findings | Where-Object Status -eq $s).Count }

    $categories = $findings | Group-Object Category | ForEach-Object {
        $sc = Get-EdepAuditScore $_.Group
        [pscustomobject]@{
            Name  = $_.Name
            Score = $sc.Score
            Open  = @($_.Group | Where-Object Status -eq 'FAIL').Count
            Rated = [bool]$sc.Max
        }
    } | Where-Object Rated | Sort-Object Score

    $now = Get-Date
    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
    $report = [pscustomobject]@{
        Profile        = 'EDEP-Audit'
        Version        = $EdepVersion
        Language       = $lang
        Computer       = $env:COMPUTERNAME
        Os             = if ($os) { "$($os.Caption) $($os.Version)" } else { 'Windows' }
        Checked        = $now.ToString('o')
        CheckedDisplay = $now.ToString((Get-EdepText 'date.format'))
        IsAdmin        = $isAdmin
        Score          = Get-EdepAuditScore $findings
        Counts         = [pscustomobject]$counts
        Categories     = @($categories)
        Findings       = @($findings)
        HtmlPath       = $null
    }

    # Konsolenausgabe
    $colors = @{ PASS = 'Green'; WARN = 'Yellow'; FAIL = 'Red'; UNKNOWN = 'DarkGray'; INFO = 'Cyan' }
    $order = @{ FAIL = 0; WARN = 1; UNKNOWN = 2; INFO = 3; PASS = 4 }
    Write-Host ''
    Write-Host (Get-EdepText 'ui.headline' @($report.Computer, $report.Score.Score, $report.Score.Grade)) -ForegroundColor White
    Write-Host (Get-EdepText 'ui.counts' @($counts.FAIL, $counts.WARN, $counts.PASS, $counts.UNKNOWN)) -ForegroundColor Gray
    Write-Host ''
    foreach ($f in ($findings | Sort-Object { $order[$_.Status] }, { - $_.Weight })) {
        Write-Host ('{0,-8} {1}' -f $f.Status, $f.Title) -ForegroundColor $colors[$f.Status]
        if ($f.Status -ne 'PASS') { Write-Host ('         {0}' -f $f.Detail) -ForegroundColor DarkGray }
    }
    if (-not $isAdmin) {
        Write-Host ''
        Write-Host (Get-EdepText 'ui.noadmin') -ForegroundColor Yellow
    }

    if (-not $NoHtml) {
        if (-not (Test-Path -LiteralPath $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }
        $file = Join-Path $OutputPath ("edep-audit-{0}-{1}.html" -f $env:COMPUTERNAME, $now.ToString('yyyyMMdd-HHmm'))
        [IO.File]::WriteAllText($file, (ConvertTo-EdepAuditHtml $report), [Text.UTF8Encoding]::new($false))
        $report.HtmlPath = $file
        Write-Host ''
        Write-Host (Get-EdepText 'ui.report' @($file)) -ForegroundColor Cyan
        if ($Open) { Start-Process $file }
    }

    if ($PassThru) { $report }
}
