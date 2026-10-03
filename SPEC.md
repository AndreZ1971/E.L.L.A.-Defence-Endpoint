# E.D. Endpoint Profile (EDEP)

**Offenes Sicherheitsprofil für Windows-Endgeräte: Outbound-Zero-Trust, Telemetrie-Souveränität und deterministische Isolation**

|               |                                                            |
| ------------- | ---------------------------------------------------------- |
| **Version**   | 0.1.0                                                      |
| **Status**    | Entwurf (Draft) — nicht versiegelt, Änderungen erwartet    |
| **Datum**     | 2026-09-30                                                 |
| **Autor**     | Andre Zabel                                                |
| **Plattform** | Windows 11 (22H2+) und Windows Server 2022+, x64 und ARM64 |
| **Lizenz**    | MIT                                                        |

---

## 0. Normative Sprache

Die Schlüsselwörter **MUSS**, **DARF NICHT**, **SOLL**, **SOLL NICHT** und **KANN** sind im Sinne von
[RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) (MUST, MUST NOT, SHOULD, SHOULD NOT, MAY) zu lesen.

Jede Anforderung hat eine eindeutige ID der Form `EDEP-<BEREICH>-<NN>`, eine Konformitätsstufe
(L1/L2/L3) und mindestens einen Konformitätstest in [conformance/README.md](conformance/README.md).
**Eine Anforderung ohne Test ist keine Anforderung.**

---

## 1. Zweck und Abgrenzung

EDEP definiert, was ein Windows-Endgerät technisch erzwingen muss, damit gilt:

1. **Kein Programm spricht ins Netz, das nicht ausdrücklich dafür zugelassen ist** (Outbound-Zero-Trust).
2. **Das Betriebssystem selbst überträgt nur die technisch unvermeidliche Telemetrie**, und der Nutzer sieht, was blockiert ist.
3. **Jede Durchsetzungsentscheidung ist lokal protokolliert** und für den Nutzer einsehbar.
4. **Bei einem erkannten Datenabfluss isoliert sich der Host deterministisch** — nicht auf Basis einer Modellvermutung.

EDEP ist **kein Antivirus** und ersetzt keinen. EDEP ist ein Eindämmungs- und Souveränitätsprofil:
Es geht davon aus, dass Schadcode auf den Rechner gelangen _kann_, und sorgt dafür, dass er von dort
möglichst nichts erreicht. EDEP ist mit Microsoft Defender und anderen AV-Produkten kombinierbar und
empfiehlt diese Kombination ausdrücklich.

### 1.1 Grundprinzipien

| Prinzip                                               | Bedeutung                                                                                                                                         |
| ----------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------- |
| **P1 — Bordmittel zuerst**                            | Was Windows selbst erzwingen kann (Windows Defender Firewall / WFP, App Control for Business, Gruppenrichtlinien), wird genutzt statt nachgebaut. |
| **P2 — Kein eigener Kernel-Code, solange vermeidbar** | Eigene Kernel-Treiber sind das größte Stabilitäts- und Angriffsrisiko. L1 und L2 sind ohne eigenen Treiber erreichbar.                            |
| **P3 — Deterministisch setzt durch, Modelle beraten** | Nur Regeln mit reproduzierbarem Ergebnis dürfen blockieren oder isolieren. Sprachmodelle dürfen ausschließlich Hinweise erzeugen.                 |
| **P4 — Offline-first**                                | Keine Anforderung setzt eine Cloud-Verbindung des Herstellers voraus.                                                                             |
| **P5 — Ehrliche Grenzen**                             | Was EDEP nicht leisten kann, steht in Abschnitt 3.3 — und darf in keiner Produktbeschreibung verschwiegen werden.                                 |

---

## 2. Konformitätsstufen

| Stufe  | Name     | Umsetzung                                                                                                                                                              | Eigener Code                                        |
| ------ | -------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------- |
| **L1** | Baseline | Ausschließlich Windows-Bordmittel, per Skript anwendbar und prüfbar ([baseline/L1](baseline/L1/))                                                                      | Nein                                                |
| **L2** | Enforced | Agent (User-Mode-Dienst) verwaltet WFP-Filter über die offizielle API, bindet Netzwerkrechte an kryptografische Programmidentität, persistente und Boot-Time-Filter    | Ja, **ohne** Kernel-Treiber                         |
| **L3** | Isolated | L2 plus deterministische Notfall-Isolation, lokale Anomalieerkennung auf Verbindungs-Metadaten, optional beratendes lokales Modell und optional Hardware-Trennschalter | Ja, Kernel-Callout nur optional (siehe EDEP-NET-09) |

Eine Stufe gilt als erreicht, wenn **alle MUSS-Anforderungen dieser und aller niedrigeren Stufen**
ihre Konformitätstests bestehen. Teilerfüllung ist keine Konformität.

Eine Implementierung KANN zusätzlich im **Audit-Modus** betrieben werden (protokollieren statt
blockieren). Ein System im Audit-Modus ist **nicht konform**, sondern „in Einführung“.

---

## 3. Bedrohungsmodell

### 3.1 Schutzgüter

- **S1** Nutzerdaten auf dem Host (Dateien, Zugangsdaten, Browserdaten)
- **S2** Verhaltens- und Nutzungsdaten (Telemetrie, Aktivitätsverlauf, Werbe-ID)
- **S3** Das lokale Netz (Schutz vor lateraler Bewegung, die vom Host ausgeht)
- **S4** Integrität und Nachvollziehbarkeit der Schutzmaßnahmen selbst

### 3.2 Angreifer im Geltungsbereich

| ID     | Angreifer                                                              | Beispiel                                                                              | Adressiert durch                                  |
| ------ | ---------------------------------------------------------------------- | ------------------------------------------------------------------------------------- | ------------------------------------------------- |
| **A1** | Netzwerk-Scanner von außen                                             | Portscan, Dienst-Fingerprinting                                                       | NET-01, NET-02                                    |
| **A2** | Schadcode mit **Benutzerrechten** in einem nicht zugelassenen Programm | Loader, Infostealer, Makro-Payload                                                    | NET-03, ID-01..03                                 |
| **A3** | Missbrauch von Windows-Bordwerkzeugen (LOLBins)                        | `powershell`, `curl.exe`, `certutil`, `bitsadmin`, `mshta` laden nach oder leiten aus | NET-04                                            |
| **A4** | Betriebssystem- und Hersteller-Telemetrie ohne aktive Zustimmung       | DiagTrack, Werbe-ID, Aktivitätsverlauf                                                | TEL-01..05                                        |
| **A5** | Datenabfluss über ein **zugelassenes** Programm oder über DNS          | Browser fernsteuern, DNS-Tunneling                                                    | NET-06, ISO-02, INF-01 (nur Erkennung, siehe 3.3) |
| **A6** | Laterale Bewegung vom Host ins lokale Netz                             | SMB/RDP/WinRM zu Nachbarsystemen                                                      | NET-05                                            |

### 3.3 Ausdrücklich **nicht** im Geltungsbereich (Restrisiken)

Diese Grenzen sind normativ: Eine konforme Implementierung DARF NICHT behaupten, sie abzudecken.

- **R1 — Angreifer mit Administrator- oder SYSTEM-Rechten.** Wer Admin ist, kann Firewall-Regeln
  löschen, Dienste beenden und Richtlinien ändern. EDEP kann das auf L1/L2 nur **protokollieren und
  erkennen** (LOG-03), nicht verhindern. Echter Selbstschutz (Protected Process Light) setzt einen
  ELAM-Treiber voraus, den nur Mitglieder der Microsoft Virus Initiative erhalten [Q-13].
- **R2 — Angreifer im Kernel** (Treiber, Bootkits). Außerhalb jeder User-Mode-Kontrolle.
- **R3 — Inhalt verschlüsselter Verbindungen.** EDEP sieht bei TLS/QUIC nur Metadaten
  (Ziel, Port, Volumen, Zeitmuster, ggf. SNI). Eine Inhaltsprüfung erforderte TLS-Interception mit
  eigener Stammzertifizierungsstelle; diese ist in EDEP **untersagt** (EDEP-INF-04), weil sie selbst
  ein erhebliches Risiko erzeugt.
- **R4 — Missbrauch zugelassener Programme.** Wird ein zugelassener Browser ferngesteuert, ist der
  Verkehr aus Sicht der Programmidentität legitim. EDEP reduziert das Risiko über enge Regeln und
  Erkennung (L3), beseitigt es aber nicht.
- **R5 — Kompromittierte signierte Software** (Lieferkettenangriff auf einen zugelassenen Hersteller).
- **R6 — Physischer Zugriff** auf das Gerät.

### 3.4 Bekannte Umgehungen (normativ)

Diese Wege an der Durchsetzung vorbei sind bekannt. Sie stehen hier, **bevor** jemand sie als
Schwäche „entdeckt“. Jede Umgehung hat einen Konformitätstest, der ihr Verhalten dokumentiert
(T-BYP-xx in [conformance/README.md](conformance/README.md)). Eine Implementierung **DARF NICHT**
behaupten, eine dieser Umgehungen zu verhindern, wenn ihr Test das nicht belegt.

| ID       | Umgehung                                                                                                                                                                                | Betrifft          | Gegenmaßnahme in EDEP                                                                             | Rest                                                                         |
| -------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------- | ------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------- |
| **B-01** | **BITS-Jobs.** Jeder Benutzer kann über den Dienst BITS Dateien laden und hochladen (MITRE ATT&CK T1197) [Q-09]. EDEP sieht für Windows Update eine Erlaubnisregel für den Dienst BITS vor. | L1, L2 | LOG-06 (Erkennung über Ereignis 3/59). L2 **SOLL** BITS-Jobs von Nicht-Administratoren melden. | Auf L1 Erkennung (LOG-06). **Gemessen (Lauf 0, Windows-Sandbox, und Lauf 1, Hyper-V-VM mit Windows 11 Enterprise 25H2):** Im Enforce-Modus wird die Übertragung eines Benutzers **blockiert**, die Dienstregel für BITS lässt sie nicht durch, siehe [E-71, E-73](docs/EVIDENCE.md). Warum, ist ungeklärt. Ob die Umgehung auf anderen Systemen oder mit anderer Regelart doch gelingt, ist offen; im Audit-Modus wurde sie nicht erneut gemessen (R-A6 gelang vor EDEP). |
| **B-02** | **DNS-Tunnel.** Daten werden in DNS-Anfragen kodiert und über den erlaubten DNS-Client-Dienst gesendet (T1071.004) [Q-11].                                                              | L1, L2            | NET-06 (nur konfigurierte Resolver), L3 Anomalieerkennung auf Namenseigenschaften.                | Geringe Bandbreite, aber möglich.                                            |
| **B-03** | **Missbrauch oder Übernahme erlaubter Programme** (Fernsteuerung, Code-Injektion in einen erlaubten Prozess desselben Benutzers).                                                       | alle              | Wenige, eng gefasste Freigaben; ASR-Regeln; L3 Volumen- und Ziel-Anomalien.                       | Grundsätzliche Grenze jeder programmbasierten Firewall (R4).                 |
| **B-04** | **Austausch einer erlaubten Datei oder DLL-Sideloading**, wenn der Pfad für Benutzer schreibbar ist.                                                                                    | L1                | NET-10 (nur admin-geschützte Pfade); ID-02 (App Control erzwingend, ab L2).                       | Ohne erzwingendes App Control kann ein Admin weiterhin DLLs platzieren (R1). |
| **B-05** | **Authenticated-Bypass-Regeln** der Windows-Firewall setzen Blockregeln außer Kraft [Q-05].                                                                                             | L1                | NET-04 verbietet sie ausgehend.                                                                   | Anlegen erfordert Admin (R1).                                                |
| **B-06** | **Fremder WFP-Sublayer mit höherem Gewicht und _hard permit_** setzt sich gegen EDEP-Blockaden durch [Q-04].                                                                            | L2, L3            | NET-07 (höchstes Gewicht, Überwachung).                                                           | Anlegen erfordert Admin (R1).                                                |
| **B-07** | **Umbenannte oder kopierte LOLBins** (z. B. `curl.exe` als `%TEMP%\x.exe`) treffen keine pfadbasierte Blockregel.                                                                       | L1 im Audit-Modus | Im Enforce-Modus greift die Standard-Blockade (NET-03); die LOLBin-Regeln sind zusätzliche Tiefe. | Keiner im Enforce-Modus.                                                     |
| **B-08** | **Uneingeschränkte ausgehende Erlaubnisregel.** Eine aktive Regel ohne Programm-, Dienst-, Paket-, Port- und Adressbindung hebt `ausgehend: Block` auf. Gemessen in der Windows-Sandbox (`Container: allow outbound`, vom Image bei jedem Start neu angelegt), 2026-10-02. | L1, L2 | NET-03 prüft die Wirkung (keine uneingeschränkte Regel); T-NET-03b, T-BYP-08. | Anlegen erfordert Adminrechte (R1). Eine **eingeschränkte, aber breite** Regel (z. B. alle Ziele auf Port 443 für jedes Programm) wird **nicht** erkannt. |

### 3.5 Betriebsmodell: Aktualisierungen unter ausgehender Sperre (normativ für Enforce)

Eine Sperre aller nicht freigegebenen ausgehenden Verbindungen (EDEP-NET-03) und die Pflicht, sicherheitsrelevante
Aktualisierungen einzuspielen (EDEP-TEL-04), stehen im Konflikt. Gemessen ist, dass der mitgelieferte L1 diesen Konflikt
auf Windows nicht zuverlässig löst ([DD-13](docs/DESIGN-DECISIONS.md), [E-84, E-88, E-89](docs/EVIDENCE.md), [Lauf 3](conformance/runs/2026-10-03-Enterprise25H2-26200.9550-HyperV-Lauf3/run.md)).
Deshalb **MUSS** der Betreiber, der den Enforce-Modus einsetzt, **vorher einen der folgenden Wege festlegen und dokumentieren**:

| Weg | Beschreibung | Stand der Messung |
| --- | --- | --- |
| **A. Zentraler Update-Server** | Die Clients beziehen Aktualisierungen von einem internen Update-Server (WSUS, Intune/Endpoint Manager, Update-Proxy). Der Betreiber legt für dessen Adresse und Port eine eigene Erlaubnisregel an. | Nicht Teil des mitgelieferten L1, **nicht gemessen** |
| **B. Wartungsfenster** | Der Betreiber nimmt den Enforce-Modus für die Dauer der Aktualisierung zurück (`Restore-EdepL1` oder Audit-Modus), spielt die Aktualisierungen ein und wendet `-Enforce` danach erneut an. Nach jedem Schritt prüft er mit `Test-EdepL1`. | Zurücknehmen und erneutes Anwenden sind gemessen (Läufe 1 bis 3), die **Updateinstallation im Fenster ist nicht gemessen** |
| **C. `-AllowWindowsUpdate`** | Domainregeln für `svchost.exe` (DD-13). | **Nicht zuverlässig** (Enterprise: im ersten Messblock 0 von 9 Versuchen); nur als Hilfe, nicht als Betriebsmodell |

Ohne festgelegten Weg ist der Enforce-Modus **nicht empfohlen**. Für Einzelplatzrechner ohne eigenen Update-Weg gilt der
Audit-Modus mit den Sperren nach EDEP-NET-04 und EDEP-TEL-02 (siehe README). `Test-EdepL1` meldet unter Enforce für
EDEP-TEL-04 einen Hinweis mit Handlungsanweisung auf diesen Abschnitt; er ersetzt die Festlegung des Weges nicht.

### 3.6 Bekannte Einschränkungen der L1-Referenzimplementierung

Stand `0.1.0-draft`. Diese Punkte sind **ungeklärt oder ungemessen** und werden nicht als erfüllt dargestellt:

- **Rücknahme (E-76).** Nach `Restore-EdepL1` und Neustart kam der EDEP-Zustand in zwei von sechs gültigen Versuchen zurück (Lauf 1 und 2; Lauf 3: sauber). Die Ursache ist unbekannt. Randbedingung: Nach jeder Rücknahme und jedem Neustart **MUSS** der Zustand mit `Test-EdepL1` geprüft werden (EDEP-OPS-01).
- **Defender-Komponenten (E-85).** `MDCoreSvc` wird unter ausgehender Sperre abgewiesen; Defender-Signaturupdates schlagen mit `-AllowWindowsUpdate` überwiegend fehl.
- **DiagTrack-Sperre (E-86).** Die Dienstregel aus EDEP-TEL-02 hat `DiagTrack` in einer kleinen Messung auf Enterprise 25H2 **nicht** blockiert ([Messprotokoll](conformance/runs/2026-10-03-Enterprise25H2-26200.9550-HyperV-E86/run.md)); der Test meldet WARN. Nicht gemessen: Pro, Telemetrie-Level 0, `dmwappushservice`, eine Programmregel als Ersatz.
- **SYSTEM-initiierte Scans (E-87).** Token und Verhalten unter ausgehender Sperre sind nicht gemessen.
- **Nicht geprüft:** fremder Virenschutz (Netzwerkschutz-Voraussetzung), DoH, Windows 11 Home, Windows Server, andere Sprachen, Updateinstallation unter Enforce.

---

## 4. Anforderungen

### 4.1 Netzwerk (NET)

| ID              | Stufe | Anforderung                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| --------------- | ----- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **EDEP-NET-01** | L1    | Die Windows Defender Firewall **MUSS** in allen Profilen (Domain, Private, Public) aktiv sein, mit Standardaktion **Block** für eingehende Verbindungen.                                                                                                                                                                                                                                                                                                                                                                                                          |
| **EDEP-NET-02** | L1    | Der Stealth-Modus **DARF NICHT** deaktiviert sein (`DisableStealthMode` ≠ 0 weder unter `HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\<Profil>`, einschließlich `PrivateProfile` und `StandardProfile`, noch im lokalen Firewall-Schlüssel): Der Host sendet für geschlossene Ports weder ICMP-Unreachable noch TCP-Reset [Q-06]. Tarpitting ist **nicht** vorgeschrieben (DD-09).                                                                                                                                                                            |
| **EDEP-NET-03** | L1 | Die Standardaktion für **ausgehende** Verbindungen **MUSS** in allen Profilen **Block** sein. Ausgehender Verkehr ist nur über ausdrückliche Erlaubnisregeln pro Programm oder Dienst zulässig. Zusätzlich **DARF KEINE** aktive ausgehende Erlaubnisregel ohne jede Einschränkung existieren (kein Programm, Dienst, Paket und Besitzer, Protokoll `Any` oder `TCP`, alle Ports, alle Adressen), weil sie die Standardsperre aufhebt (B-08). *Einordnung:* Microsoft nennt ausgehendes Blockieren eine Option „for certain highly secure environments“ und empfiehlt für die meisten Umgebungen „allow outbound“ zugunsten einfacher Softwareverteilung [Q-05]. EDEP entscheidet sich bewusst für Sicherheit vor Bequemlichkeit (DD-12). |
| **EDEP-NET-04** | L1    | Für die Programme der LOLBin-Liste (Anhang A) **MÜSSEN** explizite ausgehende Blockregeln existieren. Blockregeln haben in der Windows-Firewall Vorrang vor Erlaubnisregeln, **außer** vor Regeln mit „Authenticated Bypass“ (IPsec, „Blockregeln außer Kraft setzen“) [Q-05]. Solche Regeln **DÜRFEN** ausgehend **NICHT** existieren.                                                                                                                                                                                                                           |
| **EDEP-NET-05** | L1    | Eingehende Freigaben für SMB (445), RDP (3389), WinRM (5985/5986) und RPC-Endpunktzuordnung (135) **DÜRFEN NICHT** im Profil _Public_ aktiv sein.                                                                                                                                                                                                                                                                                                                                                                                                                 |
| **EDEP-NET-06** | L2    | DNS-Auflösung **SOLL** auf konfigurierte Resolver beschränkt sein; direkte ausgehende Verbindungen auf Port 53/853 von anderen Prozessen als dem DNS-Client-Dienst **MÜSSEN** blockiert sein.                                                                                                                                                                                                                                                                                                                                                                     |
| **EDEP-NET-07** | L2    | Der Agent **MUSS** seine Filter über die offizielle WFP-Verwaltungs-API (`FwpmFilterAdd0` o. ä.) in einem eigenen Sublayer mit eigenem Provider anlegen und **DARF NICHT** fremde Filter verändern. Sein Sublayer **MUSS** das höchste Gewicht aller Sublayer haben: Ein normaler WFP-Block ist ein _hard block_ und in keinem anderen Sublayer aufhebbar, ein _hard permit_ in einem **höher** priorisierten Sublayer setzt sich aber durch [Q-04]. Taucht ein fremder Sublayer mit höherem Gewicht auf, **MUSS** das als Manipulation gemeldet werden (LOG-03). |
| **EDEP-NET-08** | L2    | Die Default-Block-Filter des Agenten **MÜSSEN** in **zwei getrennten Sätzen** existieren: als Boot-Time-Filter (`FWPM_FILTER_FLAG_BOOTTIME`, wirksam ab Start von `tcpip.sys` bis zum Start der BFE) **und** als persistente Filter (`FWPM_FILTER_FLAG_PERSISTENT`, wirksam ab BFE-Start). Beide Flags **DÜRFEN NICHT** an einem Filter kombiniert werden [Q-02]. Der Übergang ist laut Microsoft atomar [Q-03]. Der Provider **MUSS** einem Windows-Dienst mit Starttyp _Automatisch_ zugeordnet sein, sonst deaktiviert die BFE seine Filter beim Start [Q-02]. |
| **EDEP-NET-09** | L3    | Ein eigener WFP-Callout-Treiber **KANN** eingesetzt werden, aber nur für Funktionen, die ohne ihn nicht umsetzbar sind (z. B. Stream-Metadaten). Er **MUSS** WHCP-/Attestation-signiert sein, **DARF NICHT** undokumentierte Kernel-Strukturen verwenden und **MUSS** bei eigenem Fehler den Verkehr blockieren (fail-closed) statt das System anzuhalten.                                                                                                                                                                                                        |
| **EDEP-NET-10** | L1    | Programme, denen ausgehender Netzzugang erlaubt wird, **MÜSSEN** in einem Pfad liegen, den nur Administratoren, SYSTEM und TrustedInstaller ändern können (Datei und alle übergeordneten Ordner). Sonst kann Schadcode mit Benutzerrechten die erlaubte Datei ersetzen oder eine DLL daneben ablegen und erbt die Freigabe (Umgehung B-04).                                                                                                                                                                                                                       |

### 4.2 Programmidentität (ID)

| ID             | Stufe | Anforderung                                                                                                                                                                                                                                                                                                               |
| -------------- | ----- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **EDEP-ID-01** | L1    | Eine App-Control-for-Business-Richtlinie (WDAC) **MUSS** aktiv sein, auf L1 mindestens im Audit-Modus.                                                                                                                                                                                                                    |
| **EDEP-ID-02** | L2    | Die App-Control-Richtlinie **MUSS** im erzwingenden Modus aktiv sein.                                                                                                                                                                                                                                                     |
| **EDEP-ID-03** | L2    | Ausgehende Netzwerkrechte **MÜSSEN** an eine kryptografische Programmidentität gebunden sein: Authenticode-Signatur (Herausgeber + Produktname) **oder** SHA-256-Datei-Hash. Ein Pfad allein ist **keine** Identität. Die Prüfung erfolgt beim Verbindungsaufbau (WFP-ALE-Ebene) bzw. beim Prozessstart, nicht pro Paket. |
| **EDEP-ID-04** | L2    | Ändert sich die Identität einer zugelassenen Datei (Update, Austausch), **MUSS** das Netzwerkrecht erlöschen, bis die neue Identität zugelassen ist. Bei Signatur-Bindung bleibt ein Update desselben Herausgebers gültig; bei Hash-Bindung nicht.                                                                        |
| **EDEP-ID-05** | L2    | Dienste, die in `svchost.exe` laufen, **MÜSSEN** über ihre Dienst-SID adressiert werden, nicht über `svchost.exe` als Programm. Eine Pauschalerlaubnis für `svchost.exe` ist **unzulässig**. **Hinweis (Lauf 1, [E-73](docs/EVIDENCE.md)):** Bei der Windows-Firewall lassen Erlaubnisregeln mit `-Service` die Verbindungen von `wuauserv` und `BITS` nicht durch. Ein Mitschnitt mit festgehaltenen Dienst-PIDs zeigt, dass `wuauserv` und BITS bei Aufträgen aus dem Benutzerprozess mit dem Token des **Benutzers ohne Dienst-SID** verbinden ([E-84](docs/EVIDENCE.md)); die Annahme „Dienst-SID adressierbar“ gilt also nicht für jeden Dienst und ist **vor dem Bau von L2 zu klären**.                                                                                                                              |

### 4.3 Telemetrie (TEL)

| ID              | Stufe | Anforderung                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| --------------- | ----- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **EDEP-TEL-01** | L1    | Die Richtlinie `AllowTelemetry` **MUSS** auf den niedrigsten von der Edition unterstützten Wert gesetzt sein. „Diagnostic data off“ (0) gibt es nur auf Enterprise, Education und Server; auf Home/Pro ist „Required“ (1) die niedrigste Stufe [Q-07]. Die Implementierung **MUSS** dem Nutzer den tatsächlich wirksamen Wert anzeigen. _Zielkonflikt:_ Microsoft empfiehlt bei Nutzung von Windows Update mindestens „Required“, weil sonst keine Daten zu Update-Fehlern übermittelt werden [Q-07]. EDEP priorisiert Datensparsamkeit; das **MUSS** in der Betreiberdokumentation stehen. |
| **EDEP-TEL-02** | L1    | Für die Dienste `DiagTrack` und `dmwappushservice` **MÜSSEN** explizite ausgehende Blockregeln existieren. Dienstbezogene Regeln wirken nur, wenn der Dienst den SID-Typ `RESTRICTED` oder `UNRESTRICTED` hat [Q-08]; das **MUSS** geprüft werden (`sc.exe qsidtype`). _Abweichung von Microsoft:_ Microsoft rät, `settings-win.data.microsoft.com` nicht zu sperren [Q-07]. EDEP sperrt den Telemetriedienst vollständig und nimmt in Kauf, dass sich Telemetrieeinstellungen nicht mehr fernsteuern lassen. **Hinweis (Lauf 2, [E-86](docs/EVIDENCE.md)):** `DiagTrack` verbindet mit dem Benutzer-Token ohne Dienst-SID. **Gemessen ([Messprotokoll E-86](conformance/runs/2026-10-03-Enterprise25H2-26200.9550-HyperV-E86/run.md)):** Die dienstbezogene Regel hat `DiagTrack` auf Windows 11 Enterprise 25H2 nicht blockiert (eine Verbindung trotz Regel, keine blockierte); `Test-EdepL1` meldet TEL-02 daher als **WARN**. Die Wirkung ist nicht belegt.                                                                               |
| **EDEP-TEL-03** | L1 | Die Werbe-ID **MUSS** per Richtlinie abgeschaltet sein (`AdvertisingInfo\DisabledByGroupPolicy = 1`) [Q-25]. Der Aktivitätsverlauf **MUSS** abgeschaltet sein, und zwar Erfassung, Veröffentlichung und Upload (`System\EnableActivityFeed = 0`, `System\PublishUserActivities = 0`, `System\UploadUserActivities = 0`), wie von Microsoft empfohlen [Q-26]. |
| **EDEP-TEL-04** | L1    | Sicherheitsrelevante Aktualisierungen (Windows Update, Defender-Signaturen, Zertifikatssperrlisten) **DÜRFEN NICHT** blockiert werden. Telemetrie-Blockaden über IP-Listen oder Hosts-Dateien sind **unzulässig**, weil sie sich Infrastruktur mit Update-Diensten teilen und bei CDN-Wechseln wirkungslos oder schädlich werden. Blockiert wird über Dienst- und Programmidentität. **Stand der Messung (Lauf 1, Enterprise 25H2, [E-73, E-74](docs/EVIDENCE.md)):** Der mitgelieferte L1 erfüllt diese Anforderung im Enforce-Modus **nicht** (gemessen auf Windows 11 Enterprise 25H2 und Pro 26H2). Die Windows-Update-Suche und `Update-MpSignature` scheitern, weil dienstbezogene Erlaubnisregeln für `wuauserv` und `BITS` nicht greifen; eine Programmregel für `svchost.exe` würde helfen, ist aber breit. `Test-EdepL1` hat TEL-04 dort trotzdem mit PASS gemeldet, weil es Regeln prüfte und nicht die Wirkung; nach der Korrektur meldet es unter „ausgehend Block“ ohne Messung WARN und mit `-ProbeUpdates` bei scheiternder Update-Suche FAIL ([E-81](docs/EVIDENCE.md)). Zusätzlich wird die Defender-Regel bei jedem Plattform-Update ungültig, bis der Installer erneut läuft. **Stand nach Lauf 3 ([Protokoll](conformance/runs/2026-10-03-Enterprise25H2-26200.9550-HyperV-Lauf3/run.md)):** Die Option ist nicht zuverlässig (Enterprise: im ersten Block 0 von 9 Versuchen). Der Enforce-Modus ist daher **nur zusammen mit einem definierten Update-Weg** (WSUS, Intune, Proxy) empfohlen. **Umsetzung ([DD-13](docs/DESIGN-DECISIONS.md), [E-88](docs/EVIDENCE.md)):** Mit `Install-EdepL1 -AllowWindowsUpdate` (Regeln „Programm `svchost.exe` + Update-Domains“, Netzwerkschutz von Defender nötig) gelingen Update-Suche und BITS zu Microsoft unter Enforce; ohne die Option meldet `Test-EdepL1` FAIL. Ungemessen: Neustart, Updateinstallation, Defender-Signaturen, fremder Virenschutz ([E-89](docs/EVIDENCE.md)).                                                                                                                                                                                                        |
| **EDEP-TEL-05** | L2    | Der Dienst `DiagTrack` **SOLL** deaktiviert sein.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |

### 4.4 Protokollierung (LOG)

| ID              | Stufe | Anforderung                                                                                                                                                                                                                                                       |
| --------------- | ----- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **EDEP-LOG-01** | L1    | Verworfene Verbindungen **MÜSSEN** protokolliert werden: Firewall-Log (`LogBlocked = True`) **und** Sicherheitsüberwachung „Filterplattformverbindung“ (Fehler; Ereignis 5157).                                                                                   |
| **EDEP-LOG-02** | L1    | Protokolle **MÜSSEN** ausschließlich lokal gespeichert werden. Eine Weiterleitung **DARF** nur mit ausdrücklicher Konfiguration durch den Nutzer bzw. Betreiber erfolgen.                                                                                         |
| **EDEP-LOG-03** | L2    | Der Agent **MUSS** Manipulationen an seinen Filtern, seiner Richtlinie und am Firewall-Zustand erkennen (Abgleich Soll/Ist mindestens alle 60 s sowie bei WFP-Änderungsereignissen) und als eigenes Ereignis protokollieren.                                      |
| **EDEP-LOG-04** | L2    | Jede Durchsetzungsentscheidung des Agenten (erlaubt, blockiert, isoliert, Modus-Wechsel) **MUSS** mit Zeitstempel, Programmidentität, Ziel und auslösender Regel-ID protokolliert werden. Das Protokoll **MUSS** für den Nutzer ohne Spezialwerkzeug lesbar sein. |
| **EDEP-LOG-05** | L2    | Das Agentenprotokoll **SOLL** hash-verkettet sein (jeder Eintrag enthält den SHA-256 des Vorgängers), sodass nachträgliches Entfernen erkennbar ist.                                                                                                              |
| **EDEP-LOG-06** | L1    | Das Protokoll `Microsoft-Windows-Bits-Client/Operational` **MUSS** aktiv sein. Es verzeichnet jeden BITS-Job mit Besitzer (Ereignis 3) und übertragener Adresse (Ereignis 59) und ist auf L1 das einzige Erkennungsmittel für die Umgehung B-01 [Q-10].           |

### 4.5 Isolation (ISO)

| ID              | Stufe | Anforderung                                                                                                                                                                                                                                                                                                                                                             |
| --------------- | ----- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **EDEP-ISO-01** | L3    | Die Implementierung **MUSS** einen Isolationsmodus besitzen, der sämtlichen Netzwerkverkehr außer Loopback blockiert. Er **MUSS** über persistente WFP-Filter mit höchstem Gewicht im eigenen Sublayer umgesetzt werden (nicht durch Deaktivieren des Adapters), damit er Neustarts überdauert und nicht durch erneutes Aktivieren eines Adapters umgangen werden kann. |
| **EDEP-ISO-02** | L3    | Die Isolation **DARF** nur durch deterministische Auslöser erfolgen: (a) Zugriff auf eine Köderdatei (Canary), (b) Überschreiten eines konfigurierten Volumenschwellwerts zu nicht zugelassenen oder erstmals gesehenen Zielen, (c) erkannte Manipulation (LOG-03), (d) manuelle Auslösung.                                                                             |
| **EDEP-ISO-03** | L3    | Ein Sprachmodell oder anderes nicht-deterministisches Verfahren **DARF NICHT** alleiniger Auslöser einer Isolation oder Blockade sein.                                                                                                                                                                                                                                  |
| **EDEP-ISO-04** | L3    | Die Aufhebung der Isolation **MUSS** eine lokale, interaktive Bestätigung durch einen Administrator erfordern. Eine Aufhebung aus der Ferne **DARF NICHT** möglich sein.                                                                                                                                                                                                |
| **EDEP-ISO-05** | L3    | Ein physischer Trennschalter **KANN** zusätzlich unterstützt werden. Er gilt nur dann als „Hardware-Killswitch“, wenn er elektrisch außerhalb der Kontrolle des Betriebssystems trennt. Das Deaktivieren eines Adapters per Treiberbefehl **DARF NICHT** so bezeichnet werden.                                                                                          |

### 4.6 Lokale Inferenz (INF)

| ID              | Stufe | Anforderung                                                                                                                                                                                                        |
| --------------- | ----- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **EDEP-INF-01** | L3    | Lokale Anomalieerkennung **KANN** auf Verbindungs-Metadaten erfolgen (Ziel, Port, Volumen, Rate, Zeitmuster, Prozess, DNS-Namenseigenschaften).                                                                    |
| **EDEP-INF-02** | L3    | Ein Sprachmodell **DARF** nur beraten: Es erzeugt Hinweise mit Begründung für den Nutzer. Es **DARF NICHT** Regeln ändern, blockieren oder isolieren.                                                              |
| **EDEP-INF-03** | L3    | Eingaben an das Modell (z. B. Domänennamen, Prozessnamen) sind **nicht vertrauenswürdig** und können vom Angreifer gesteuert sein (Prompt Injection). Der Modellprozess **MUSS** selbst ohne Netzwerkrecht laufen. |
| **EDEP-INF-04** | alle  | TLS-Interception (eigene Stammzertifizierungsstelle, Aufbrechen verschlüsselter Verbindungen) ist **unzulässig**.                                                                                                  |
| **EDEP-INF-05** | L3    | Der Ressourcenverbrauch der Inferenz **MUSS** begrenzt sein (Priorität, Speicherobergrenze). Unter Last **MUSS** auf deterministische Heuristiken zurückgefallen werden.                                           |

### 4.7 Betrieb und Ausfallsicherheit (OPS)

| ID              | Stufe | Anforderung                                                                                                                                                                                                                      |
| --------------- | ----- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **EDEP-OPS-01** | L1    | Vor jeder Änderung **MUSS** der bisherige Zustand gesichert werden, und es **MUSS** ein dokumentierter Wiederherstellungsweg existieren. **Hinweis (Lauf 1, [E-76](docs/EVIDENCE.md)):** Nach der Wiederherstellung und einem Neustart ist der Zustand mit `Test-EdepL1` zu prüfen; in zwei von sechs gültigen Versuchen (je einer auf Enterprise 25H2 und Pro 26H2; Lauf 3 sauber) kam der EDEP-Zustand zurück (Ursache unbekannt).                                                                                         |
| **EDEP-OPS-02** | L1    | Jede Implementierung **MUSS** einen Audit-Modus bieten, in dem nur protokolliert und nichts blockiert wird.                                                                                                                      |
| **EDEP-OPS-03** | L2    | Ein Wartungsmodus (vorübergehend durchlässig) **MUSS** zeitlich begrenzt sein (Standard ≤ 30 min), **MUSS** lokale Admin-Bestätigung erfordern und **MUSS** protokolliert werden. Er **DARF NICHT** Isolation (ISO-01) aufheben. |
| **EDEP-OPS-04** | L2    | Stürzt der Agent ab, **MÜSSEN** die persistenten Filter weiter gelten (fail-closed).                                                                                                                                             |
| **EDEP-OPS-05** | alle  | In-Memory-Hooks in fremde Prozesse (z. B. zum Entfernen von UI-Werbung) sind **nicht Teil** von EDEP und **DÜRFEN NICHT** als Sicherheitsfunktion beworben werden.                                                               |

### 4.8 Richtlinie (POL)

| ID              | Stufe | Anforderung                                                                                                                                                 |
| --------------- | ----- | ----------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **EDEP-POL-01** | L2    | Die Konfiguration **MUSS** als maschinenlesbare Richtlinie vorliegen, die gegen [schema/edep-policy.schema.json](schema/edep-policy.schema.json) validiert. |
| **EDEP-POL-02** | L2    | Die Richtliniendatei **MUSS** nur für Administratoren schreibbar sein; ihr SHA-256 **MUSS** bei jedem Laden protokolliert werden.                           |
| **EDEP-POL-03** | L2    | Eine ungültige Richtlinie **DARF NICHT** zu einem offeneren Zustand führen: Der Agent behält die zuletzt gültige Richtlinie bei.                            |

---

## 5. Konformität

- Tests: [conformance/README.md](conformance/README.md)
- L1 automatisch prüfbar: [baseline/L1/Test-EdepL1.ps1](baseline/L1/Test-EdepL1.ps1)
- Eine Konformitätsaussage **MUSS** Version des Profils, Stufe, Datum und das Prüfprotokoll enthalten:
  `EDEP 0.1.0 L1 — geprüft 2026-09-30 — 15/15 erfüllt`

---

## Anhang A — LOLBin-Liste (normativ für EDEP-NET-04)

Ausgehend zu blockieren, sofern nicht durch die Richtlinie ausdrücklich und begründet ausgenommen:

| Programm          | Pfad(e)                                                                                                                      |
| ----------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| PowerShell 5.1    | `%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe`, `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` |
| PowerShell ISE    | `%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell_ise.exe`                                                            |
| curl              | `%SystemRoot%\System32\curl.exe`, `%SystemRoot%\SysWOW64\curl.exe`                                                           |
| certutil          | `%SystemRoot%\System32\certutil.exe`, `%SystemRoot%\SysWOW64\certutil.exe`                                                   |
| bitsadmin         | `%SystemRoot%\System32\bitsadmin.exe`                                                                                        |
| mshta             | `%SystemRoot%\System32\mshta.exe`, `%SystemRoot%\SysWOW64\mshta.exe`                                                         |
| rundll32          | `%SystemRoot%\System32\rundll32.exe`, `%SystemRoot%\SysWOW64\rundll32.exe`                                                   |
| regsvr32          | `%SystemRoot%\System32\regsvr32.exe`, `%SystemRoot%\SysWOW64\regsvr32.exe`                                                   |
| wscript / cscript | `%SystemRoot%\System32\wscript.exe`, `%SystemRoot%\System32\cscript.exe`                                                     |
| msbuild           | `%SystemRoot%\Microsoft.NET\Framework*\v4.0.30319\MSBuild.exe`                                                               |
| InstallUtil       | `%SystemRoot%\Microsoft.NET\Framework*\v4.0.30319\InstallUtil.exe`                                                           |
| hh                | `%SystemRoot%\hh.exe`                                                                                                        |

Hinweis: Das Blockieren von `powershell.exe` betrifft auch legitime Administrationsskripte mit
Netzwerkzugriff (z. B. `Install-Module`). Diese Ausnahme ist bewusst in Kauf genommen; der
Wartungsmodus (OPS-03) bzw. eine begründete Ausnahme in der Richtlinie ist der vorgesehene Weg.

## Anhang B — Quellen

Jede mit [Q-xx] markierte Aussage stützt sich auf die hier genannte Quelle. Geprüft am
2026-09-30. Das vollständige Nachweisregister, auch für Aussagen ohne Quellenmarke, steht in
[docs/EVIDENCE.md](docs/EVIDENCE.md).

| ID | Quelle | Belegt |
|---|---|---|
| Q-01 | Microsoft Learn: [Managing CI policies and tokens with CiTool](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/operations/citool-commands) | CiTool-Befehle, `-json`, Bedeutung „Is Currently Enforced“ |
| Q-02 | Microsoft Learn: [FWPM_FILTER0 structure](https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_filter0) | PERSISTENT und BOOTTIME nicht kombinierbar; Filter werden deaktiviert ohne auto-startenden Dienst des Providers |
| Q-03 | Microsoft Learn: [WFP Operation](https://learn.microsoft.com/en-us/windows/win32/fwp/basic-operation) | Boot-Time-Filter ab `tcpip.sys`, atomarer Übergang zu persistenten Filtern; ALE-Klassifizierung beim ersten Paket eines Flusses |
| Q-04 | Microsoft Learn: [Filter Arbitration](https://learn.microsoft.com/en-us/windows/win32/fwp/filter-arbitration) | Filter-Block = hard block; hard permit in höherem Sublayer; Veto |
| Q-05 | Microsoft Learn: [Windows Firewall Rules](https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/rules); [Authenticated Bypass](https://learn.microsoft.com/es-es/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc754873(v=ws.10)) | Block vor Allow; Ausnahme Authenticated Bypass; Microsofts Einordnung von Outbound-Block; keine Platzhalter in Programmpfaden |
| Q-06 | Microsoft: [Disable stealth mode in Windows (KB2586744)](https://support.microsoft.com/en-us/kb/2586744); [MS-GPFAS 2.2.3.2](https://msdn.microsoft.com/en-us/library/ff720058.aspx) | Wirkung des Stealth-Modus; Registrierungsschlüssel inkl. `PrivateProfile` |
| Q-07 | Microsoft Learn: [Configure Windows diagnostic data in your organization](https://learn.microsoft.com/en-us/windows/privacy/configure-windows-diagnostic-data-in-your-organization) | Stufen 0–3; „off“ nur Enterprise/Education/Server; Empfehlung „Required“ bei Windows Update; Endpunkt `settings-win` |
| Q-08 | Microsoft Learn: [Create an Inbound Program or Service Rule (WS2012)](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/jj717295(v=ws.11)) | Dienstregeln nur bei SID-Typ RESTRICTED/UNRESTRICTED; `sc qsidtype` |
| Q-09 | MITRE ATT&CK: [T1197 BITS Jobs](https://attack.mitre.org/techniques/T1197/) | BITS als Umgehung programmbasierter Firewalls |
| Q-10 | Microsoft TechNet: [BITS Event ID 59](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-r2-and-2008/dd408518(v=ws.10)); [Event ID 60 — Jobs](https://technet.microsoft.com/en-us/library/cc734635(v=ws.10)) | Ereignisse der BITS-Clientprotokollierung |
| Q-11 | MITRE ATT&CK: [T1071.004 DNS](https://attack.mitre.org/techniques/T1071/004/) | DNS-Tunnel |
| Q-12 | Microsoft Learn: [Deploy App Control policies using script](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/deployment/deploy-appcontrol-policies-with-script) | `{PolicyId}.cip`, `CiTool --update-policy` ab Windows 11 22H2 |
| Q-13 | Microsoft Learn: [Protecting anti-malware services](https://learn.microsoft.com/en-us/windows/desktop/Services/protecting-anti-malware-services-); [ELAM driver requirements](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/elam-driver-requirements) | PPL nur mit ELAM-Treiber; ELAM nur für MVI-Mitglieder |
| Q-14 | Windows Experience Blog: [The Windows Resiliency Initiative](https://blogs.windows.com/windowsexperience/2025/06/26/the-windows-resiliency-initiative-building-resilience-for-a-future-ready-enterprise) | Sicherheitsprodukte außerhalb des Kernels |
| Q-15 | Microsoft Support: [PowerShell 2.0 removal from Windows (KB5065506)](https://support.microsoft.com/help/5065506) | Entfernung ab Windows 11 24H2 (August 2025) |
| Q-16 | Microsoft Learn: [Configure ASR rules](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-configure) | ASR-Aktionen 0/1/2/6 |
| Q-17 | Microsoft Learn: [Turn on network protection](https://learn.microsoft.com/en-us/defender-endpoint/enable-network-protection) | Network Protection 0/1/2 |
| Q-18 | Microsoft Learn: [Detect, enable, and disable SMBv1, SMBv2, and SMBv3](https://learn.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3) | SMBv1-Client `mrxsmb10` |
| Q-19 | Microsoft Learn: [NetbiosOptions](https://learn.microsoft.com/en-us/windows-hardware/customize/desktop/unattend/microsoft-windows-netbt-interfaces-interface-netbiosoptions) | 0 = DHCP, 1 = an, 2 = aus |
| Q-20 | Microsoft Learn: [about_Logging_Windows](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows) | Skriptblockprotokollierung |
| Q-21 | Microsoft Learn: [WFP Auditing and Logging](https://learn.microsoft.com/en-us/windows/win32/fwp/auditing-and-logging) | Ereignis 5157, Unterkategorie Filterplattformverbindung |
| Q-22 | CISA: [CM0053 Disable LLMNR](https://www.cisa.gov/eviction-strategies-tool/info-countermeasures/CM0053) | `EnableMulticast = 0` |
| Q-23 | Microsoft Learn: [App Control AppId tagging guide](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/appidtagging/appcontrol-appid-tagging-guide) | Firewall-Regeln per `PolicyAppId` |
| Q-24 | [LOLBAS-Projekt](https://lolbas-project.github.io/) | Anhang A |
| Q-25 | Microsoft Learn: [Privacy Policy CSP, DisableAdvertisingId](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-privacy) | GP-Zuordnung `Software\Policies\Microsoft\Windows\AdvertisingInfo` → `DisabledByGroupPolicy` |
| Q-26 | Microsoft Learn: [Manage connections from Windows operating system components to Microsoft services, Abschnitt 18.22](https://learn.microsoft.com/en-us/windows/privacy/manage-connections-from-windows-operating-system-components-to-microsoft-services) | `EnableActivityFeed = 0`, `PublishUserActivities = 0`, `UploadUserActivities = 0` unter `HKLM\Software\Policies\Microsoft\Windows\System` |
| Q-27 | Microsoft Learn: [Troubleshoot Windows Update error code 0x8024002E](https://learn.microsoft.com/en-us/troubleshoot/windows-server/installing-updates-features-roles/troubleshoot-windows-update-error-code-0x8024002e) | Zugriff auf Windows Update deaktiviert (oft per Gruppenrichtlinie) |
| Q-28 | Microsoft Learn: [Error 80072EE6 when downloading updates from WSUS](https://learn.microsoft.com/en-us/troubleshoot/windows-client/deployment/error-80072ee6-downlaod-wsus-update) | ungültige URL im Richtlinienwert „Specify intranet Microsoft update service location“ |

Weiterführend: NIST SP 800-207 (Zero Trust Architecture); BSI SiSyPHuS Win10 (Telemetrie);
CIS Microsoft Windows 11 Benchmark.

Inspiriert von der [E.L.L.A. Directive](https://github.com/AndreZ1971/The-E.L.L.A.-Directive-),
einem Schutzprotokoll für autonome lokale KI-Agenten. EDEP ist davon unabhängig: Es ist
weder Teil der Directive noch Voraussetzung für deren Konformität, und umgekehrt.
