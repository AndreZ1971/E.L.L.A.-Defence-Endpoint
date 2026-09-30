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
  erkennen** (LOG-03), nicht verhindern. Echter Selbstschutz (Protected Process Light) ist
  Teilnehmern der Microsoft Virus Initiative vorbehalten.
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

---

## 4. Anforderungen

### 4.1 Netzwerk (NET)

| ID              | Stufe | Anforderung                                                                                                                                                                                                                                                                                                                                                |
| --------------- | ----- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **EDEP-NET-01** | L1    | Die Windows Defender Firewall **MUSS** in allen Profilen (Domain, Private, Public) aktiv sein, mit Standardaktion **Block** für eingehende Verbindungen.                                                                                                                                                                                                   |
| **EDEP-NET-02** | L1    | Der Stealth-Modus **DARF NICHT** deaktiviert sein: Unerwünschte eingehende Pakete werden ohne Antwort verworfen. Tarpitting ist **nicht** vorgeschrieben (auf einem Endgerät bindet es eigene Ressourcen ohne nennenswerten Schutzgewinn).                                                                                                                 |
| **EDEP-NET-03** | L1    | Die Standardaktion für **ausgehende** Verbindungen **MUSS** in allen Profilen **Block** sein. Ausgehender Verkehr ist nur über ausdrückliche Erlaubnisregeln pro Programm oder Dienst zulässig.                                                                                                                                                            |
| **EDEP-NET-04** | L1    | Für die Programme der LOLBin-Liste (Anhang A) **MÜSSEN** explizite ausgehende Blockregeln existieren. Blockregeln haben in der Windows-Firewall Vorrang vor Erlaubnisregeln; eine spätere zu breite Erlaubnisregel hebt sie daher nicht auf.                                                                                                               |
| **EDEP-NET-05** | L1    | Eingehende Freigaben für SMB (445), RDP (3389), WinRM (5985/5986) und RPC-Endpunktzuordnung (135) **DÜRFEN NICHT** im Profil _Public_ aktiv sein.                                                                                                                                                                                                          |
| **EDEP-NET-06** | L2    | DNS-Auflösung **SOLL** auf konfigurierte Resolver beschränkt sein; direkte ausgehende Verbindungen auf Port 53/853 von anderen Prozessen als dem DNS-Client-Dienst **MÜSSEN** blockiert sein.                                                                                                                                                              |
| **EDEP-NET-07** | L2    | Der Agent **MUSS** seine Filter über die offizielle WFP-Verwaltungs-API (`FwpmFilterAdd0` o. ä.) in einem eigenen WFP-Sublayer mit eigenem Provider anlegen und **DARF NICHT** fremde Filter verändern.                                                                                                                                                    |
| **EDEP-NET-08** | L2    | Die Default-Block-Filter des Agenten **MÜSSEN** als persistente Filter (`FWPM_FILTER_FLAG_PERSISTENT`) **und** als Boot-Time-Filter (`FWPM_FILTER_FLAG_BOOTTIME`) existieren, sodass zwischen Systemstart und Dienststart kein ungefilterter Zeitraum entsteht.                                                                                            |
| **EDEP-NET-09** | L3    | Ein eigener WFP-Callout-Treiber **KANN** eingesetzt werden, aber nur für Funktionen, die ohne ihn nicht umsetzbar sind (z. B. Stream-Metadaten). Er **MUSS** WHCP-/Attestation-signiert sein, **DARF NICHT** undokumentierte Kernel-Strukturen verwenden und **MUSS** bei eigenem Fehler den Verkehr blockieren (fail-closed) statt das System anzuhalten. |

### 4.2 Programmidentität (ID)

| ID             | Stufe | Anforderung                                                                                                                                                                                                                                                                                                               |
| -------------- | ----- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **EDEP-ID-01** | L1    | Eine App-Control-for-Business-Richtlinie (WDAC) **MUSS** aktiv sein, auf L1 mindestens im Audit-Modus.                                                                                                                                                                                                                    |
| **EDEP-ID-02** | L2    | Die App-Control-Richtlinie **MUSS** im erzwingenden Modus aktiv sein.                                                                                                                                                                                                                                                     |
| **EDEP-ID-03** | L2    | Ausgehende Netzwerkrechte **MÜSSEN** an eine kryptografische Programmidentität gebunden sein: Authenticode-Signatur (Herausgeber + Produktname) **oder** SHA-256-Datei-Hash. Ein Pfad allein ist **keine** Identität. Die Prüfung erfolgt beim Verbindungsaufbau (WFP-ALE-Ebene) bzw. beim Prozessstart, nicht pro Paket. |
| **EDEP-ID-04** | L2    | Ändert sich die Identität einer zugelassenen Datei (Update, Austausch), **MUSS** das Netzwerkrecht erlöschen, bis die neue Identität zugelassen ist. Bei Signatur-Bindung bleibt ein Update desselben Herausgebers gültig; bei Hash-Bindung nicht.                                                                        |
| **EDEP-ID-05** | L2    | Dienste, die in `svchost.exe` laufen, **MÜSSEN** über ihre Dienst-SID adressiert werden, nicht über `svchost.exe` als Programm. Eine Pauschalerlaubnis für `svchost.exe` ist **unzulässig**.                                                                                                                              |

### 4.3 Telemetrie (TEL)

| ID              | Stufe | Anforderung                                                                                                                                                                                                                                                                                                                                                                          |
| --------------- | ----- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **EDEP-TEL-01** | L1    | Die Richtlinie `AllowTelemetry` **MUSS** auf den niedrigsten von der Edition unterstützten Wert gesetzt sein (0 = _Security_ auf Enterprise/Education/Server; auf Home/Pro wirkt 0 wie 1 = _Required_). Die Implementierung **MUSS** dem Nutzer den tatsächlich wirksamen Wert anzeigen.                                                                                             |
| **EDEP-TEL-02** | L1    | Für die Dienste `DiagTrack` und `dmwappushservice` **MÜSSEN** explizite ausgehende Blockregeln existieren.                                                                                                                                                                                                                                                                           |
| **EDEP-TEL-03** | L1    | Werbe-ID (`AdvertisingInfo\DisabledByGroupPolicy = 1`) und Upload des Aktivitätsverlaufs (`PublishUserActivities = 0`, `UploadUserActivities = 0`) **MÜSSEN** per Richtlinie deaktiviert sein.                                                                                                                                                                                       |
| **EDEP-TEL-04** | L1    | Sicherheitsrelevante Aktualisierungen (Windows Update, Defender-Signaturen, Zertifikatssperrlisten) **DÜRFEN NICHT** blockiert werden. Telemetrie-Blockaden über IP-Listen oder Hosts-Dateien sind **unzulässig**, weil sie sich Infrastruktur mit Update-Diensten teilen und bei CDN-Wechseln wirkungslos oder schädlich werden. Blockiert wird über Dienst- und Programmidentität. |
| **EDEP-TEL-05** | L2    | Der Dienst `DiagTrack` **SOLL** deaktiviert sein.                                                                                                                                                                                                                                                                                                                                    |

### 4.4 Protokollierung (LOG)

| ID              | Stufe | Anforderung                                                                                                                                                                                                                                                       |
| --------------- | ----- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **EDEP-LOG-01** | L1    | Verworfene Verbindungen **MÜSSEN** protokolliert werden: Firewall-Log (`LogBlocked = True`) **und** Sicherheitsüberwachung „Filterplattformverbindung“ (Fehler; Ereignis 5157).                                                                                   |
| **EDEP-LOG-02** | L1    | Protokolle **MÜSSEN** ausschließlich lokal gespeichert werden. Eine Weiterleitung **DARF** nur mit ausdrücklicher Konfiguration durch den Nutzer bzw. Betreiber erfolgen.                                                                                         |
| **EDEP-LOG-03** | L2    | Der Agent **MUSS** Manipulationen an seinen Filtern, seiner Richtlinie und am Firewall-Zustand erkennen (Abgleich Soll/Ist mindestens alle 60 s sowie bei WFP-Änderungsereignissen) und als eigenes Ereignis protokollieren.                                      |
| **EDEP-LOG-04** | L2    | Jede Durchsetzungsentscheidung des Agenten (erlaubt, blockiert, isoliert, Modus-Wechsel) **MUSS** mit Zeitstempel, Programmidentität, Ziel und auslösender Regel-ID protokolliert werden. Das Protokoll **MUSS** für den Nutzer ohne Spezialwerkzeug lesbar sein. |
| **EDEP-LOG-05** | L2    | Das Agentenprotokoll **SOLL** hash-verkettet sein (jeder Eintrag enthält den SHA-256 des Vorgängers), sodass nachträgliches Entfernen erkennbar ist.                                                                                                              |

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
| **EDEP-OPS-01** | L1    | Vor jeder Änderung **MUSS** der bisherige Zustand gesichert werden, und es **MUSS** ein dokumentierter Wiederherstellungsweg existieren.                                                                                         |
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
  `EDEP 0.1.0 L1 — geprüft 2026-09-30 — 13/13 PASS`

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

## Anhang B — Bezugsdokumente

- NIST SP 800-207 — Zero Trust Architecture
- BSI SiSyPHuS Win10 — Analyse der Telemetriekomponenten in Windows 10
- Microsoft Learn — Windows Filtering Platform; App Control for Business; Configure Windows diagnostic data
- CIS Microsoft Windows 11 Benchmark (Firewall-Abschnitte)
- LOLBAS-Projekt (lolbas-project.github.io)

Inspiriert von der [E.L.L.A. Directive](https://github.com/AndreZ1971/The-E.L.L.A.-Directive-),
einem Schutzprotokoll für autonome lokale KI-Agenten. EDEP ist davon unabhängig: Es ist
weder Teil der Directive noch Voraussetzung für deren Konformität, und umgekehrt.
