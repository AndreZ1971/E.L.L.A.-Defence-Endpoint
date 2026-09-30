# EDEP-Audit: bewertet, wie offen ein Windows-System für Datenabfluss und Angriffe ist.
# Setzt EdepL1.Common.ps1 und EdepL1.Checks.ps1 voraus. Ändert nichts am System.

# ---------------------------------------------------------------------------
# Katalog: Titel, Kategorie, Gewicht, Begründung und Empfehlung je Prüfung.
# Gewicht 0 = wird angezeigt, geht aber nicht in die Punktzahl ein.
# ---------------------------------------------------------------------------
$script:EdepAuditCatalog = [ordered]@{
    'EDEP-NET-03' = @{
        Title = 'Ausgehender Verkehr standardmäßig blockiert'; Category = 'Ausgehender Verkehr'; Weight = 10
        Why   = 'Ist ausgehender Verkehr standardmäßig erlaubt, kann jedes Programm, auch Schadcode, ungehindert Daten senden und Befehle nachladen. Windows lässt ausgehend standardmäßig alles zu, auch mit Defender.'
        Fix   = 'Ausgehende Standardaktion auf Block setzen und nur benötigte Programme freigeben (Install-EdepL1.ps1 -Enforce -AllowProgram ...). Vorher im Audit-Modus das Firewall-Log auswerten.'
    }
    'EDEP-NET-04' = @{
        Title = 'Windows-Bordwerkzeuge (LOLBins) ausgehend gesperrt'; Category = 'Ausgehender Verkehr'; Weight = 8
        Why   = 'Angreifer laden Schadcode bevorzugt mit Bordwerkzeugen wie PowerShell, curl, certutil oder mshta nach, weil diese signiert und überall vorhanden sind.'
        Fix   = 'Ausgehende Blockregeln für die Programme aus SPEC.md Anhang A anlegen (Install-EdepL1.ps1 erledigt das auch im Audit-Modus).'
    }
    'EDEP-NET-10' = @{
        Title = 'Freigegebene Programme nur durch Admins änderbar'; Category = 'Ausgehender Verkehr'; Weight = 6
        Why   = 'Liegt ein Programm mit Netzfreigabe in einem Ordner, den der Benutzer beschreiben darf (z. B. AppData), kann Schadcode die Datei austauschen oder eine DLL daneben legen und erbt die Freigabe.'
        Fix   = 'Programme systemweit unter C:\Program Files installieren oder die Freigabe entfernen. In EDEP L2 wird die Freigabe zusätzlich an Signatur oder Hash gebunden.'
    }
    'EDEP-LOG-06' = @{
        Title = 'BITS-Übertragungen werden protokolliert'; Category = 'Protokollierung'; Weight = 3
        Why   = 'Über den Windows-Dienst BITS kann jeder Benutzer Dateien laden und hochladen, auch wenn Programme sonst gesperrt sind (MITRE ATT&CK T1197). Das Protokoll ist das Erkennungsmittel.'
        Fix   = 'Protokoll Microsoft-Windows-Bits-Client/Operational aktivieren (wevtutil sl Microsoft-Windows-Bits-Client/Operational /e:true).'
    }
    'EDEP-TEL-02' = @{
        Title = 'Telemetrie-Dienste ausgehend gesperrt'; Category = 'Telemetrie'; Weight = 4
        Why   = 'DiagTrack und dmwappushservice übertragen Diagnose- und Nutzungsdaten an Microsoft.'
        Fix   = 'Ausgehende Blockregeln auf Dienstebene (nicht per IP- oder Hosts-Liste, das bricht Updates).'
    }
    'EDEP-NET-01' = @{
        Title = 'Firewall aktiv, eingehend blockiert'; Category = 'Eingehender Verkehr'; Weight = 8
        Why   = 'Ohne aktive Firewall sind alle lauschenden Dienste aus dem Netz erreichbar.'
        Fix   = 'Firewall in allen Profilen aktivieren, eingehende Standardaktion Block.'
    }
    'EDEP-NET-02' = @{
        Title = 'Stealth-Modus aktiv'; Category = 'Eingehender Verkehr'; Weight = 3
        Why   = 'Im Stealth-Modus antwortet der Rechner nicht auf Anfragen an geschlossene Ports und ist für Scanner schwerer zu erkennen.'
        Fix   = 'Registrierungswert DisableStealthMode entfernen oder auf 0 setzen.'
    }
    'EDEP-NET-05' = @{
        Title = 'SMB/RDP/WinRM/RPC in öffentlichen Netzen gesperrt'; Category = 'Eingehender Verkehr'; Weight = 5
        Why   = 'In Hotel-, Bahn- oder Café-WLANs sind Datei- und Fernwartungsdienste ein häufiger Einstiegspunkt.'
        Fix   = 'Eingehende Blockregel im Profil Public für TCP 135, 445, 3389, 5985, 5986.'
    }
    'EDEP-ID-01' = @{
        Title = 'App Control for Business aktiv'; Category = 'Programmkontrolle'; Weight = 6
        Why   = 'App Control legt fest, welcher Code überhaupt starten darf, und wird vom Windows-Kernel durchgesetzt.'
        Fix   = 'Mit der Richtlinie DefaultWindows_Audit im Audit-Modus beginnen (Install-EdepL1.ps1 -DeployAppControlAudit), Protokolle auswerten, dann erzwingen.'
    }
    'EDEP-TEL-01' = @{
        Title = 'Telemetrie auf niedrigster Stufe'; Category = 'Telemetrie'; Weight = 3
        Why   = 'Ohne Richtlinie können optionale Diagnosedaten übertragen werden.'
        Fix   = 'Richtlinie AllowTelemetry auf 0 setzen (wirkt auf Home/Pro als 1 = Required).'
    }
    'EDEP-TEL-03' = @{
        Title = 'Werbe-ID und Aktivitätsverlauf deaktiviert'; Category = 'Telemetrie'; Weight = 2
        Why   = 'Werbe-ID und Aktivitätsverlauf ermöglichen Profilbildung. Microsoft empfiehlt selbst, den Verlauf abzuschalten, nicht nur seinen Upload.'
        Fix   = 'Richtlinien AdvertisingInfo\DisabledByGroupPolicy=1 sowie System\EnableActivityFeed=0, PublishUserActivities=0, UploadUserActivities=0.'
    }
    'EDEP-TEL-04' = @{
        Title = 'Sicherheitsupdates erreichbar'; Category = 'Telemetrie'; Weight = 5
        Why   = 'Wer beim Abschotten Windows Update, Defender-Signaturen oder Zertifikatsprüfungen blockiert, macht das System unsicherer.'
        Fix   = 'Dienste wuauserv, BITS, DoSvc, CryptSvc, W32Time und Defender ausgehend erlauben.'
    }
    'EDEP-LOG-01' = @{
        Title = 'Blockierte Verbindungen werden protokolliert'; Category = 'Protokollierung'; Weight = 4
        Why   = 'Ohne Protokoll bleibt unbemerkt, welche Programme wohin senden wollten.'
        Fix   = 'Firewall-Log für verworfene Pakete und Überwachung „Filterplattformverbindung“ (Ereignis 5157) aktivieren.'
    }
    'EDEP-LOG-02' = @{
        Title = 'Firewall-Log bleibt lokal'; Category = 'Protokollierung'; Weight = 2
        Why   = 'Protokolle sollen nur mit ausdrücklicher Entscheidung das Gerät verlassen.'
        Fix   = 'LogFileName auf einen lokalen Pfad setzen.'
    }
    'EDEP-OPS-01' = @{
        Title = 'EDEP-Sicherung vorhanden'; Category = 'Betrieb'; Weight = 0
        Why   = 'Nur relevant, wenn EDEP angewendet wurde: Ohne Sicherung gibt es keinen sauberen Rückweg.'
        Fix   = 'Install-EdepL1.ps1 legt vor jeder Änderung eine Sicherung an.'
    }
    'AUD-SMB1' = @{
        Title = 'SMBv1-Client nicht aktiv'; Category = 'Angriffsfläche'; Weight = 5
        Why   = 'SMBv1 ist veraltet und war Einfallstor von WannaCry und NotPetya.'
        Fix   = 'Windows-Feature „SMB 1.0/CIFS-Dateifreigabeunterstützung“ entfernen.'
    }
    'AUD-LLMNR' = @{
        Title = 'LLMNR deaktiviert'; Category = 'Angriffsfläche'; Weight = 3
        Why   = 'Über LLMNR-Antworten kann ein Angreifer im selben Netz Namensauflösungen fälschen und Anmelde-Hashes abgreifen.'
        Fix   = 'Richtlinie „Multicastnamensauflösung deaktivieren“ (DNSClient\EnableMulticast = 0).'
    }
    'AUD-NETBIOS' = @{
        Title = 'NetBIOS über TCP/IP deaktiviert'; Category = 'Angriffsfläche'; Weight = 2
        Why   = 'NetBIOS-Namensdienst ermöglicht denselben Angriff wie LLMNR und verrät Rechner- und Benutzernamen.'
        Fix   = 'Pro Netzwerkadapter NetBIOS über TCP/IP deaktivieren (NetbiosOptions = 2).'
    }
    'AUD-RDP' = @{
        Title = 'Remotedesktop aus oder mit NLA'; Category = 'Angriffsfläche'; Weight = 4
        Why   = 'Offenes RDP ist einer der häufigsten Einstiegspunkte für Ransomware. Ohne Netzwerkebenen-Authentifizierung (NLA) ist der Anmeldebildschirm ungeschützt erreichbar.'
        Fix   = 'Remotedesktop deaktivieren oder zumindest NLA erzwingen und nur über VPN erreichbar machen.'
    }
    'AUD-PSV2' = @{
        Title = 'PowerShell 2.0 entfernt'; Category = 'Angriffsfläche'; Weight = 3
        Why   = 'Mit „powershell -Version 2“ umgehen Angreifer Skriptprotokollierung und AMSI.'
        Fix   = 'Windows-Feature „Windows PowerShell 2.0“ entfernen.'
    }
    'AUD-NETPROT' = @{
        Title = 'Defender Network Protection aktiv'; Category = 'Ausgehender Verkehr'; Weight = 4
        Why   = 'Network Protection blockiert Verbindungen zu bekannten Schad- und Phishing-Zielen für alle Programme, nicht nur im Browser.'
        Fix   = 'Set-MpPreference -EnableNetworkProtection Enabled'
    }
    'AUD-ASR' = @{
        Title = 'Defender-ASR-Regeln im Blockiermodus'; Category = 'Programmkontrolle'; Weight = 3
        Why   = 'Attack-Surface-Reduction-Regeln stoppen typische Angriffsketten, z. B. Office-Makros, die Prozesse starten.'
        Fix   = 'ASR-Regeln zunächst im Audit-, dann im Blockiermodus aktivieren (Add-MpPreference -AttackSurfaceReductionRules_Ids ...).'
    }
    'AUD-PSLOG' = @{
        Title = 'PowerShell-Skriptblockprotokollierung aktiv'; Category = 'Protokollierung'; Weight = 2
        Why   = 'Ohne Skriptblockprotokoll ist nicht nachvollziehbar, welcher PowerShell-Code ausgeführt wurde.'
        Fix   = 'Richtlinie „PowerShell-Skriptblockprotokollierung aktivieren“ (ScriptBlockLogging\EnableScriptBlockLogging = 1).'
    }
    'AUD-LISTEN' = @{
        Title = 'Aus dem Netz erreichbare Dienste'; Category = 'Angriffsfläche'; Weight = 0
        Why   = 'Jeder Prozess, der auf einer Nicht-Loopback-Adresse lauscht, ist potenziell von außen erreichbar, sofern die Firewall es zulässt.'
        Fix   = 'Nicht benötigte Dienste beenden; benötigte nur im Profil Domain/Private freigeben.'
    }
}

function Get-EdepAuditExtraResult {
    [CmdletBinding()]
    param([bool]$IsAdmin)

    $results = [System.Collections.Generic.List[object]]::new()
    function Add-Result([string]$Id, [string]$Status, [string]$Detail) {
        $results.Add([pscustomobject]@{ Id = $Id; Status = $Status; Detail = $Detail })
    }

    # --- SMBv1 ---------------------------------------------------------------
    $smb1 = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10' -ErrorAction SilentlyContinue
    if (-not $smb1) { Add-Result 'AUD-SMB1' 'PASS' 'SMBv1-Client-Treiber nicht installiert' }
    elseif ($smb1.Start -eq 4) { Add-Result 'AUD-SMB1' 'WARN' 'SMBv1-Client-Treiber installiert, aber deaktiviert' }
    else { Add-Result 'AUD-SMB1' 'FAIL' "SMBv1-Client-Treiber aktiv (Start=$($smb1.Start))" }

    # --- LLMNR ---------------------------------------------------------------
    $llmnr = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name EnableMulticast -ErrorAction SilentlyContinue
    if ($llmnr -and $llmnr.EnableMulticast -eq 0) { Add-Result 'AUD-LLMNR' 'PASS' 'Per Richtlinie deaktiviert' }
    else { Add-Result 'AUD-LLMNR' 'FAIL' 'Aktiv (Windows-Standard)' }

    # --- NetBIOS über TCP/IP ---------------------------------------------------
    $ifaces = @(Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces' -ErrorAction SilentlyContinue |
        ForEach-Object { (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).NetbiosOptions })
    $enabled = @($ifaces | Where-Object { $_ -ne 2 }).Count
    if ($ifaces.Count -eq 0) { Add-Result 'AUD-NETBIOS' 'UNKNOWN' 'Keine NetBT-Schnittstellen gefunden' }
    elseif ($enabled -eq 0) { Add-Result 'AUD-NETBIOS' 'PASS' "Auf allen $($ifaces.Count) Schnittstellen deaktiviert" }
    else { Add-Result 'AUD-NETBIOS' 'FAIL' "Auf $enabled von $($ifaces.Count) Schnittstellen aktiv oder per DHCP gesteuert" }

    # --- RDP -----------------------------------------------------------------
    $ts = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -ErrorAction SilentlyContinue
    if ($ts -and $ts.fDenyTSConnections -eq 1) { Add-Result 'AUD-RDP' 'PASS' 'Remotedesktop deaktiviert' }
    else {
        $nla = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication -ErrorAction SilentlyContinue
        if ($nla -and $nla.UserAuthentication -eq 1) { Add-Result 'AUD-RDP' 'WARN' 'Remotedesktop aktiv, NLA erzwungen' }
        else { Add-Result 'AUD-RDP' 'FAIL' 'Remotedesktop aktiv ohne NLA' }
    }

    # --- PowerShell 2.0 --------------------------------------------------------
    $ps2 = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine' -ErrorAction SilentlyContinue
    if ($ps2 -and $ps2.PowerShellVersion -like '2.*') { Add-Result 'AUD-PSV2' 'FAIL' 'PowerShell-2.0-Engine installiert' }
    else { Add-Result 'AUD-PSV2' 'PASS' 'PowerShell-2.0-Engine nicht vorhanden' }

    # --- Defender: Network Protection und ASR (nur mit Adminrechten sichtbar) ---
    $mp = $null
    if ($IsAdmin) { $mp = Get-MpPreference -ErrorAction SilentlyContinue }
    $mpStatus = if ($IsAdmin) { Get-MpComputerStatus -ErrorAction SilentlyContinue } else { $null }
    if (-not $IsAdmin) {
        Add-Result 'AUD-NETPROT' 'UNKNOWN' 'Defender-Einstellungen nur mit Adminrechten lesbar'
        Add-Result 'AUD-ASR' 'UNKNOWN' 'Defender-Einstellungen nur mit Adminrechten lesbar'
    }
    elseif (-not $mp -or ($mpStatus -and -not $mpStatus.AntivirusEnabled)) {
        Add-Result 'AUD-NETPROT' 'UNKNOWN' 'Microsoft Defender ist nicht der aktive Virenschutz'
        Add-Result 'AUD-ASR' 'UNKNOWN' 'Microsoft Defender ist nicht der aktive Virenschutz'
    }
    else {
        switch ([int]$mp.EnableNetworkProtection) {
            1 { Add-Result 'AUD-NETPROT' 'PASS' 'Aktiv (Blockieren)' }
            2 { Add-Result 'AUD-NETPROT' 'WARN' 'Nur Audit-Modus' }
            default { Add-Result 'AUD-NETPROT' 'FAIL' 'Deaktiviert' }
        }
        $actions = @($mp.AttackSurfaceReductionRules_Actions | ForEach-Object { [int]$_ })
        $block = @($actions | Where-Object { $_ -eq 1 }).Count
        $audit = @($actions | Where-Object { $_ -in 2, 6 }).Count
        if ($block -gt 0) { Add-Result 'AUD-ASR' 'PASS' "$block Regel(n) blockierend, $audit im Audit/Warnmodus" }
        elseif ($audit -gt 0) { Add-Result 'AUD-ASR' 'WARN' "$audit Regel(n) nur im Audit/Warnmodus" }
        else { Add-Result 'AUD-ASR' 'FAIL' 'Keine ASR-Regel aktiv' }
    }

    # --- PowerShell-Skriptblockprotokollierung --------------------------------
    $sbl = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name EnableScriptBlockLogging -ErrorAction SilentlyContinue
    if ($sbl -and $sbl.EnableScriptBlockLogging -eq 1) { Add-Result 'AUD-PSLOG' 'PASS' 'Per Richtlinie aktiv' }
    else { Add-Result 'AUD-PSLOG' 'FAIL' 'Nicht aktiv' }

    # --- Lauschende Dienste (informativ) --------------------------------------
    $listen = @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
        Where-Object { $_.LocalAddress -notmatch '^(127\.|::1$)' })
    if ($listen.Count -eq 0) { Add-Result 'AUD-LISTEN' 'INFO' 'Keine TCP-Dienste auf externen Adressen' }
    else {
        $byProc = $listen | Group-Object OwningProcess | ForEach-Object {
            $name = (Get-Process -Id ([int]$_.Name) -ErrorAction SilentlyContinue).ProcessName
            if (-not $name) { $name = "PID $($_.Name)" }
            $ports = ($_.Group.LocalPort | Sort-Object -Unique) -join ','
            "$name ($ports)"
        }
        Add-Result 'AUD-LISTEN' 'INFO' "$($listen.Count) lauschende TCP-Endpunkte: $(($byProc | Sort-Object) -join '; ')"
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
    $statusLabel = @{ PASS = 'Erfüllt'; WARN = 'Teilweise'; FAIL = 'Offen'; UNKNOWN = 'Nicht prüfbar'; INFO = 'Info' }

    $css = @'
:root{--bg:#f6f7f9;--card:#fff;--fg:#1b1f24;--muted:#5b6571;--line:#e3e6ea;
--pass:#1a7f37;--warn:#9a6700;--fail:#cf222e;--unk:#6e7781;--info:#0969da;--accent:#0969da}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){--bg:#0d1117;--card:#161b22;--fg:#e6edf3;--muted:#8d96a0;
--line:#30363d;--pass:#3fb950;--warn:#d29922;--fail:#f85149;--unk:#8d96a0;--info:#58a6ff;--accent:#58a6ff}}
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
    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.Append('<!doctype html><html lang="de"><head><meta charset="utf-8">')
    [void]$sb.Append('<meta name="viewport" content="width=device-width,initial-scale=1">')
    [void]$sb.Append("<title>EDEP-Audit $(& $enc $Report.Computer)</title><style>$css</style></head><body><main>")
    [void]$sb.Append("<h1>EDEP-Audit: $(& $enc $Report.Computer)</h1>")
    [void]$sb.Append("<div class=`"meta`">$(& $enc $Report.Os) · geprüft $(& $enc $Report.CheckedDisplay) · EDEP $(& $enc $Report.Version) · $(if ($Report.IsAdmin) { 'mit Adminrechten' } else { 'ohne Adminrechte' })</div>")

    $c = $Report.Counts
    [void]$sb.Append('<section class="hero">')
    [void]$sb.Append("<div class=`"score`">$($Report.Score.Score)<small>/100</small></div>")
    [void]$sb.Append("<div><div class=`"grade`">Stufe $($Report.Score.Grade)</div></div>")
    [void]$sb.Append("<div class=`"counts`"><span>Offen: <b>$($c.FAIL)</b></span><span>Teilweise: <b>$($c.WARN)</b></span><span>Erfüllt: <b>$($c.PASS)</b></span><span>Nicht prüfbar: <b>$($c.UNKNOWN)</b></span></div>")
    [void]$sb.Append('</section>')

    if (-not $Report.IsAdmin) {
        [void]$sb.Append('<p class="note">Ohne Adminrechte sind einige Prüfungen nicht möglich (App Control, Überwachungsrichtlinie, Defender). Sie fließen nicht in die Punktzahl ein. Für ein vollständiges Ergebnis PowerShell als Administrator starten.</p>')
    }

    [void]$sb.Append('<h2>Kategorien</h2><div class="cats">')
    foreach ($cat in $Report.Categories) {
        [void]$sb.Append("<div class=`"cat`"><b>$(& $enc $cat.Name)</b><div class=`"meta`">$($cat.Score) % · $($cat.Open) offen</div><div class=`"bar`"><span style=`"width:$($cat.Score)%`"></span></div></div>")
    }
    [void]$sb.Append('</div><h2>Befunde</h2>')

    foreach ($f in ($Report.Findings | Sort-Object { $order[$_.Status] }, { - $_.Weight })) {
        $st = $f.Status
        [void]$sb.Append("<article class=`"f $st`"><h3><span class=`"b $st`">$($statusLabel[$st])</span>$(& $enc $f.Title)<span class=`"id`">$(& $enc $f.Id)</span></h3>")
        [void]$sb.Append("<p class=`"d`">$(& $enc $f.Detail)</p>")
        if ($st -ne 'PASS') {
            [void]$sb.Append("<p class=`"why`"><b>Warum:</b> $(& $enc $f.Why)</p>")
            [void]$sb.Append("<p class=`"fix`"><b>Empfehlung:</b> $(& $enc $f.Fix)</p>")
        }
        [void]$sb.Append('</article>')
    }

    [void]$sb.Append('<footer>Dieses Audit hat nichts am System verändert. Punktzahl: gewichtete Summe (Erfüllt = volles, Teilweise = halbes Gewicht; nicht prüfbare und informative Punkte zählen nicht). ')
    [void]$sb.Append('EDEP ist ein offener Standard: https://github.com/AndreZ1971/E.L.L.A.-Defence-Endpoint</footer>')
    [void]$sb.Append('</main></body></html>')
    $sb.ToString()
}

function Invoke-EdepAudit {
    <#
    .SYNOPSIS
        Bewertet, wie offen dieses Windows-System für Datenabfluss und Angriffe ist. Ändert nichts.

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

    .EXAMPLE
        Invoke-EdepAudit -Open
    .EXAMPLE
        Invoke-EdepAudit -NoHtml -PassThru | ConvertTo-Json -Depth 5
    #>
    [CmdletBinding()]
    param(
        [string]$OutputPath = (Get-Location).ProviderPath,
        [switch]$NoHtml,
        [switch]$Open,
        [switch]$PassThru
    )

    $isAdmin = Test-EdepIsAdmin
    $raw = @(Get-EdepL1CheckResult) + @(Get-EdepAuditExtraResult -IsAdmin $isAdmin)

    $findings = foreach ($r in $raw) {
        $meta = $EdepAuditCatalog[$r.Id]
        if (-not $meta) { continue }
        # EDEP-spezifische Sicherung ist für ein reines Audit ohne EDEP nicht relevant.
        $status = $r.Status
        if ($r.Id -eq 'EDEP-OPS-01' -and $status -eq 'FAIL') { $status = 'INFO' }
        [pscustomobject]@{
            Id = $r.Id; Status = $status; Detail = $r.Detail
            Title = $meta.Title; Category = $meta.Category; Weight = $meta.Weight
            Why = $meta.Why; Fix = $meta.Fix
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
        Computer       = $env:COMPUTERNAME
        Os             = if ($os) { "$($os.Caption) $($os.Version)" } else { 'Windows' }
        Checked        = $now.ToString('o')
        CheckedDisplay = $now.ToString('dd.MM.yyyy HH:mm')
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
    Write-Host "EDEP-Audit $($report.Computer) — $($report.Score.Score)/100 (Stufe $($report.Score.Grade))" -ForegroundColor White
    Write-Host "Offen: $($counts.FAIL)  Teilweise: $($counts.WARN)  Erfüllt: $($counts.PASS)  Nicht prüfbar: $($counts.UNKNOWN)" -ForegroundColor Gray
    Write-Host ''
    foreach ($f in ($findings | Sort-Object { $order[$_.Status] }, { - $_.Weight })) {
        Write-Host ('{0,-8} {1}' -f $f.Status, $f.Title) -ForegroundColor $colors[$f.Status]
        if ($f.Status -ne 'PASS') { Write-Host ('         {0}' -f $f.Detail) -ForegroundColor DarkGray }
    }
    if (-not $isAdmin) {
        Write-Host ''
        Write-Host 'Hinweis: Ohne Adminrechte sind einige Prüfungen nicht möglich. Für ein vollständiges Ergebnis als Administrator ausführen.' -ForegroundColor Yellow
    }

    if (-not $NoHtml) {
        if (-not (Test-Path -LiteralPath $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }
        $file = Join-Path $OutputPath ("edep-audit-{0}-{1}.html" -f $env:COMPUTERNAME, $now.ToString('yyyyMMdd-HHmm'))
        [IO.File]::WriteAllText($file, (ConvertTo-EdepAuditHtml $report), [Text.UTF8Encoding]::new($false))
        $report.HtmlPath = $file
        Write-Host ''
        Write-Host "Bericht: $file" -ForegroundColor Cyan
        if ($Open) { Start-Process $file }
    }

    if ($PassThru) { $report }
}
