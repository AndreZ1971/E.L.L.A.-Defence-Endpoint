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
  aus dem Kernel heraus. Ein neuer Standard sollte nicht gegen diese Richtung gebaut werden.

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
- WFP wertet ALE-Filter einmal pro Verbindung aus, nicht pro Paket. Eine Latenzangabe
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
