# Designentscheidungen

Dieses Dokument hält fest, **warum** EDEP vom ursprünglichen Konzept
([docs/archive/](archive/)) abweicht. Jede Entscheidung ist eine Korrektur einer
Aussage, die fachlich nicht haltbar war oder ein unnötiges Risiko erzeugt hätte.

---

## DD-01 — Kein eigener Kernel-Treiber für L1 und L2

**Vorher:** WFP-Callout-Treiber als Kern der Architektur.

**Entscheidung:** L1 nutzt nur die Windows-Firewall. L2 verwaltet WFP-Filter über die
User-Mode-API (`FwpmEngineOpen0`, `FwpmSubLayerAdd0`, `FwpmFilterAdd0`). Ein Callout ist
auf L3 optional (EDEP-NET-09).

**Begründung:**

- Filtern nach Anwendung (`FWPM_CONDITION_ALE_APP_ID`), Benutzer, Adresse und Port sowie
  persistente und Boot-Time-Filter sind **ohne** Callout möglich. Ein Callout wird nur für
  Paket- oder Stream-Inspektion und Verbindungsmanipulation (z. B. Tarpit) gebraucht.
- Ein Kernel-Treiber braucht EV-Zertifikat und Microsoft-Signierung, verlängert jeden
  Release-Zyklus und kann bei einem Fehler das System anhalten.
- Microsoft bewegt Sicherheitsprodukte seit dem CrowdStrike-Vorfall (Juli 2024) aktiv
  aus dem Kernel heraus (Windows Resiliency Initiative, SPEC Q-14). Ein neuer Standard sollte
  nicht gegen diese Richtung gebaut werden.

## DD-02 — Das Sprachmodell berät, es setzt nicht durch

**Vorher:** Das SLM analysiert Payloads und trennt autonom den Netzwerkadapter.

**Entscheidung:** EDEP-ISO-03 und EDEP-INF-02 verbieten das. Isolation nur durch
deterministische Auslöser (Köderdatei, Volumenschwelle, Manipulation, manuell).

**Begründung:**

- Das Modell verarbeitet Daten, die der Angreifer kontrolliert (Domänennamen, Inhalte).
  Hat es Durchsetzungsgewalt, ist es ein Angriffsziel: Prompt Injection kann es
  **beruhigen** (Abfluss wird nicht erkannt) oder **auslösen** (Denial of Service durch
  Selbstisolation).
- Nicht-deterministische Blockaden sind nicht reproduzierbar, nicht testbar und damit
  nicht normierbar.
- Grundsatz: Durchsetzung auf Code-Ebene, nicht auf Modell-Ebene.

## DD-03 — Metadaten statt Inhaltsprüfung, keine TLS-Interception

**Vorher:** „Semantische Inferenz / Deep Packet Inspection auf Layer 7“.

**Entscheidung:** Analyse nur von Verbindungs-Metadaten (EDEP-INF-01);
TLS-Interception ist verboten (EDEP-INF-04).

**Begründung:** Der weitaus größte Teil des Verkehrs ist TLS/QUIC-verschlüsselt. WFP sieht
Chiffretext. Inhalte wären nur mit eigener Stammzertifizierungsstelle lesbar. Diese
bricht Zertifikats-Pinning, schwächt jede Verbindung des Hosts und ist bei Kompromittierung
ein Generalschlüssel. Die Maßnahme würde mehr Risiko erzeugen, als sie abwehrt.

## DD-04 — Isolation über WFP-Filter, nicht über Adapter-Abschaltung

**Vorher:** „Hardware-Killswitch“ per Treiberbefehl an WLAN-/LAN-Adapter.

**Entscheidung:** Isolation durch persistente WFP-Blockfilter mit höchstem Gewicht
(EDEP-ISO-01). „Hardware-Killswitch“ nur für echte elektrische Trennung (EDEP-ISO-05).

**Begründung:** Ein per Software deaktivierter Adapter ist per Software wieder aktivierbar
und schützt nicht vor neu eingesteckten Adaptern (USB-LAN, Tethering). WFP-Filter gelten
für alle Schnittstellen, überdauern Neustarts und lassen Loopback für lokale Dienste zu.
Den Begriff „Hardware“ für eine Softwaremaßnahme zu verwenden, würde Nutzer über die
tatsächliche Schutzwirkung täuschen.

## DD-05 — Programmidentität per Signatur/SHA-256 statt „BLAKE3 Port- & IP-Validierung“

**Vorher:** „O(1) BLAKE3 Port- & IP-Validierung, < 5 µs“.

**Entscheidung:** Identität = Authenticode-Signatur oder SHA-256 (EDEP-ID-03), Prüfung
beim Verbindungsaufbau bzw. Prozessstart.

**Begründung:**

- Einen Hash über IP und Port zu bilden, validiert nichts; die sicherheitsrelevante
  Frage ist, **welches Programm** die Verbindung aufbaut.
- Windows, Authenticode und App Control arbeiten mit SHA-256. Ein eigenes Hashverfahren
  bringt keinen Sicherheitsgewinn, aber Inkompatibilität.
- WFP wertet ALE-Filter beim ersten Paket eines Flusses aus, nicht für jedes Paket (SPEC Q-03). Eine Latenzangabe
  gehört erst nach Messung in eine Beschreibung.

## DD-06 — App Control for Business statt eigener Prozess-Whitelist

**Vorher:** Agent „blockiert Schattenprozesse/DLLs“.

**Entscheidung:** EDEP-ID-01/-02 verlangen App Control for Business (WDAC).

**Begründung:** App Control setzt im Kernel durch (Code Integrity), deckt auch DLLs und
Treiber ab, wird von Microsoft gepflegt und ist auf Windows 11 Pro verfügbar. Ein
User-Mode-Agent könnte dasselbe nur schlechter und später (nach Prozessstart) leisten.

## DD-07 — Windhawk / UI-Hooks sind nicht Teil des Standards

**Vorher:** In-Memory-Hooks in `explorer.exe` als erste Schutzebene.

**Entscheidung:** EDEP-OPS-05 schließt sie aus dem Profil aus.

**Begründung:** Das Entfernen von Werbekacheln ist Komfort, kein Schutz. Technisch ist es
selbst Code-Injection in Systemprozesse. Es widerspricht damit der eigenen Aussage
„verhindert In-Process-Injections“ und kollidiert mit App Control (nicht signierte Module).
Wer das möchte, kann es separat betreiben. Ein Sicherheitsstandard darf es nicht als
Sicherheitsfunktion ausweisen.

## DD-08 — Telemetrie über Dienstidentität blockieren, nicht über IP-/Hostlisten

**Vorher:** „Totale Blockade“ von Diagnosediensten auf Socket-Ebene.

**Entscheidung:** Dienstbasierte Blockregeln (EDEP-TEL-02), Richtlinienwerte (TEL-01/03),
ausdrücklicher Schutz der Update-Kanäle (TEL-04).

**Begründung:** Telemetrie- und Update-Endpunkte teilen sich CDN-Infrastruktur. IP- und
Hosts-Listen veralten, blockieren versehentlich Sicherheitsupdates oder werden von
Windows ignoriert. Die Bindung an den Dienst (Dienst-SID) ist präzise und stabil. Auf
Home/Pro ist „Required“ die niedrigste Stufe. Das wird offen angezeigt statt verschwiegen.

## DD-09 — Kein Tarpitting

**Vorher:** Tarpit „friert Scan-Tools ein“.

**Entscheidung:** Nicht vorgeschrieben (EDEP-NET-02). Stilles Verwerfen reicht.

**Begründung:** Auf einem Endgerät hält Tarpitting eigene Verbindungszustände offen und
braucht einen Callout-Treiber. Moderne Scanner sind asynchron, der Bremseffekt ist gering.
Das Verwerfen ohne Antwort (Stealth) leistet die Windows-Firewall bereits.

## DD-10 — Faire Einordnung gegenüber bestehenden Produkten

**Vorher:** „Kommerzielle Suiten reagieren erst post-breach.“

**Entscheidung:** EDEP positioniert sich als **Ergänzung** zu Antivirus/EDR (SPEC.md,
Abschnitt 1).

**Begründung:** Microsoft Defender hat Network Protection, Attack Surface Reduction und
Cloud-Schutz. Die pauschale Aussage wäre falsch und würde die Glaubwürdigkeit des
Standards beschädigen. Der echte Unterschied von EDEP ist ein anderer: Ausgehender
Verkehr ist standardmäßig verboten, die Programmidentität wird durchgesetzt, alles
funktioniert ohne Cloud, der Nutzer behält die Hoheit über die Telemetrie, und alles
ist als offene, prüfbare Norm formuliert.

## DD-11 — Programmidentität mit Bordmitteln prüfen, bevor ein Agent sie nachbaut

**Befund (2026-09-30):** Die Windows-Firewall kann Regeln an App-Control-AppID-Tags binden
(`New-NetFirewallRule -PolicyAppId`, Intune „Policy App ID“). Die Tags vergibt eine
App-Control-Richtlinie anhand von Signatur oder Hash (SPEC Q-23).

**Entscheidung:** Vor der Implementierung von `wfp::apply` im L2-Agenten wird geprüft, ob
EDEP-ID-03 vollständig mit AppID-Tagging und Firewall-Regeln erfüllbar ist. Wenn ja, wird
das der Referenzweg für L2 (P1 „Bordmittel zuerst“), und der Agent beschränkt sich auf
Richtlinienverwaltung, Manipulationserkennung und Protokoll.

**Offene Prüfpunkte:** Verhalten bei Updates signierter Programme; Wechselwirkung mit
Dienst-SIDs; Verfügbarkeit auf Windows 11 Pro ohne MDM; Leistung bei vielen Tags.

## DD-12 — Bewusste Abweichungen von Microsoft-Empfehlungen

EDEP weicht an drei Stellen von Microsofts eigener Empfehlung ab. Das ist Absicht und
wird hier offen geführt, damit niemand es als Versehen „entdecken“ muss:

| Thema | Microsoft empfiehlt | EDEP verlangt | Begründung | Preis |
|---|---|---|---|---|
| Ausgehender Verkehr | „allow outbound“ für die meisten Umgebungen; Block nur „for certain highly secure environments“ (Q-05) | Block (NET-03) | Ohne Outbound-Block ist Datenabfluss für jeden Prozess offen; das ist der Kern von EDEP | Jede Anwendung braucht eine Freigabe |
| Diagnosedaten | mindestens „Required“, wenn man sich auf Windows Update verlässt (Q-07) | niedrigste Stufe der Edition (TEL-01) | Datensparsamkeit | Microsoft erhält keine Daten zu Update-Fehlern (nur Enterprise/Education/Server, auf Pro bleibt „Required“) |
| Telemetrie-Endpunkt `settings-win` | nicht sperren (Q-07) | DiagTrack vollständig sperren (TEL-02) | Ein Telemetriedienst soll gar nicht nach Hause telefonieren | Microsoft kann Telemetrieeinstellungen nicht mehr fernsteuern |

Wer EDEP einsetzt, übernimmt diese Abwägungen bewusst. Betreiberdokumentation und
Kundenkommunikation **müssen** sie nennen.

## DD-13 — Update-Erreichbarkeit unter „ausgehend Block“: Domainregeln als Option

**Problem.** Unter `-Enforce` waren Windows Update, Defender-Signaturen und BITS nicht erreichbar (gemessen auf drei
Umgebungen, E-74). Die Dienstregeln aus dem ersten Konzept (Erlaubnis nach Dienst-SID) greifen nicht, weil
`wuauserv` und BITS bei Aufträgen aus dem Benutzerprozess mit dem **Token des Benutzers und ohne Dienst-SID**
verbinden (Mitschnitt, E-84).

**Entscheidung.** `Install-EdepL1.ps1 -AllowWindowsUpdate` legt Regeln „Programm `svchost.exe`, TCP 80/443, nur zu
den Update-Domains“ an (Dynamic Keywords der Windows-Firewall). Die Option ist **standardmäßig aus**. Der
Netzwerkschutz von Defender, den die Funktion voraussetzt, wird auf den **Audit-Modus** gestellt (nur wenn er aus
war) und beim Restore zurückgestellt. EDEP-TEL-04 meldet unter Enforce ohne diese Regeln **FAIL**.

**Verworfen.**
- *Programmregel `svchost.exe` auf Port 80/443 ohne Domain:* wirksam, aber jeder Dienst in `svchost.exe` erreicht
  dann jedes Ziel auf diesen Ports.
- *Dienstregeln:* greifen nicht (E-84).
- *Option immer an:* Sie würde den Netzwerkschutz stillschweigend einschalten und L1 von Defender abhängig machen.
- *Wartungsmodus mit manuell geöffneter Regel:* hätte die Rücknahme zur Pflicht gemacht, die in 2 von 5 Versuchen
  versagt hat (E-76).

**Folgen und Grenzen.** Die Firewall lernt die Adressen aus beobachteten DNS-Antworten und verwirft sie beim Neustart;
erste Verbindungen können scheitern. Es gilt die Microsoft-Voraussetzung (Defender läuft, Netzwerkschutz an, DoH
aus, [Microsoft Learn](https://learn.microsoft.com/windows/security/operating-system-security/network-security/windows-firewall/dynamic-keywords)).
Die Domainliste stammt aus Microsofts Liste für Unternehmensnetze (Stand 2026-10-03) und ist nicht auf Vollständigkeit
für jedes System geprüft. **Die Option ist teilweise wirksam:** Die Update-Suche gelingt nach dem ersten Fehlversuch (auch nach einem Neustart ohne Cache), BITS zu Microsoft und Defender-Signaturupdates sind **nicht zuverlässig**, weil einzelne CDN-Ziele trotz passendem Namen nicht gelernt werden (E-89). **Defender-Signaturupdates sind mit dieser Option nicht gelöst** (`Update-MpSignature` scheitert weiter, ein zusätzlicher Hostname und das Race beim ersten Versuch sind offen, E-89). Ungemessen: Updateinstallation, die Suche nach einem Neustart mit leerem Cache, fremder Virenschutz.
