# Änderungsprotokoll

Format angelehnt an [Keep a Changelog](https://keepachangelog.com/de/1.1.0/).
Korrekturen an der Spezifikation stehen zusätzlich mit Begründung in
[docs/EVIDENCE.md, Errata](docs/EVIDENCE.md#errata).

## [Unveröffentlicht]

- **Zeitstempel je Release unter `timestamps/`** (`SHA256SUMS-<TAG>.ots`): Der bestätigte Beweis von draft.4 (Bitcoin-Block 969890) und der ausstehende von draft.5 liegen dort; die Datei `SHA256SUMS.ots` im Wurzelordner entfällt (das ZIP von draft.5 enthält sie noch, sie gehört zu draft.4, siehe [SIGNING.md](docs/SIGNING.md)).

## [0.1.0-draft.5] – 2026-10-10

**Entwurf, kein Konformitätsnachweis.** Ergänzt `0.1.0-draft.4`: Messungen auf Windows 11 Pro 26H2, eine Korrektur der Prüfstufe „Destructive“ und die BSI-Zuordnung zu Grundschutz++. Dieser Stand ist signiert (`SHA256SUMS`, `SHA256SUMS.sig`, signierter Tag, [SIGNING.md](docs/SIGNING.md)). Bekannte Einschränkungen: [SPEC.md, Abschnitt 3.6](SPEC.md).

### Geändert und hinzugefügt

- **`docs/BSI-MAPPING.md`: Abschnitt Grundschutz++** (Stand-der-Technik-Bibliothek, Katalog Version 2026-09-24, Zuordnung IT-GS 2023 → GS++ als Entwurf des BSI). Neu: KONF.7.15 „Lokale Firewall“, TEST.5.4 „Persistenz“, die BSI-Aussage zur Ablösung des Kompendiums mit Terminen, Abgrenzung Windows 10 und 11 (E-86).
- **Stufe „Destructive“ in der Pro-VM gemessen** ([Protokoll](conformance/runs/2026-10-10-Pro26H2-26300.9457-HyperV-Destructive/run.md), E-91): 12 von 13 Schritten, `D-E1` (Rücknahme identisch) schlug fehl, weil `Restore-EdepL1` ohne `-BackupPath` die älteste von 19 Sicherungen früherer Läufe nahm.
- **`docs/BSI-MAPPING.md`, Abschnitt C:** Zuordnung der 15 L1-Prüfungen zu den Anforderungen von Grundschutz++ (Katalog von 1000 Anforderungen, Gesichtetes und im Wortlaut Gelesenes ausgewiesen), stärkste Entsprechung KONF.2.5, Definition von „SOLLTE“ nach den Namensräumen des BSI, nicht behandelte Anforderungen, zwei Falsche Freunde (ASST.6.3, ASST.6.4). Einschätzung des Projekts, nicht bestätigt.
- **Edge-Laden auf Pro bestätigt** (Sichtprüfung des Testers, Ausgangszustand und Enforce mit `-AllowProgram`, E-93); auf Enterprise weiter offen.
- **Stufe „Destructive“ übergibt der Rücknahme ihre eigene erste Sicherung** (`-BackupPath`) und meldet ältere Sicherungen (`olderBackups`, `restoreMode` im Protokoll und als Hinweis in der Ausgabe); `Get-EdepOwnFirstBackup`, 4 neue Einheitentests (81). In der Pro-VM wiederholt: 13 von 13 Schritten, `D-E1` identisch, auch nach Neustart (E-92).
- **Bitcoin-Zeitstempel (OpenTimestamps)** für Releases: `tools/ots.py` (`stamp`, `upgrade`, `verify`, braucht nur `pip install opentimestamps`), `SHA256SUMS.ots` für `0.1.0-draft.4` (bei vier Kalendern eingereicht; **bestätigt in Bitcoin-Block 969890, 2026-10-04 19:35:29 UTC**), Beschreibung in [docs/SIGNING.md](docs/SIGNING.md). Das Werkzeug wurde an einem echten Zeitstempel geprüft (Test an einem Zeitstempel eines anderen Projekts, Bitcoin-Block 952238, 2026-06-03 16:29 UTC).

## [0.1.0-draft.4] – 2026-10-04

**Entwurf, kein Konformitätsnachweis.** Die Liste gilt seit `0.0.1`; die Tags `0.1.0-draft.1` bis `0.1.0-draft.3` sind Zwischenstände. Dieser Stand ist signiert (`SHA256SUMS`, `SHA256SUMS.sig`, signierter Tag, [SIGNING.md](docs/SIGNING.md)). Bekannte Einschränkungen: [SPEC.md, Abschnitt 3.6](SPEC.md).

### Hinzugefügt

- `Invoke-EdepAudit`: kostenloses Audit mit Punktzahl, Erklärungen und HTML-Bericht, auch ohne Adminrechte
- PowerShell-Modul `EDEP` (Manifest, Build- und Signierskript)
- Zweisprachigkeit (Deutsch/Englisch) für Audit, Prüfdetails und HTML-Bericht (`-Language`), `README.en.md`
- SPEC 3.4 „Bekannte Umgehungen“ (B-01 bis B-08) mit Umgehungstests T-BYP-01 bis T-BYP-08
- EDEP-NET-10: Freigaben nur für admin-geschützte Programmpfade
- EDEP-LOG-06: BITS-Clientprotokoll als Erkennung für B-01
- Quellenverzeichnis (SPEC Anhang B, 28 Quellen), Nachweisregister (`docs/EVIDENCE.md`),
  Prüfanleitung (`docs/VERIFY-YOURSELF.md`), `SECURITY.md`
- DD-11 (Programmidentität per App-Control-AppID-Tags prüfen), DD-12 (bewusste Abweichungen von Microsoft)
- CI: Syntax, BOM, PSScriptAnalyzer, Rauchtests, Schema-Validierung mit Negativtests
- Roadmap
- Testplan für den VM-Durchlauf (`docs/TESTPLAN-L1.md`), Protokollvorlage und erstes Protokoll (`conformance/runs/`), Fingerabdruck-Sammler
- Einheitentests `tools/Test-EdepUnits.ps1` (nachgebaute ACL, Regelerkennung, Mutationstest), in der CI
- Quellen Q-27 und Q-28 (Windows-Update-Fehlercodes); Nachweise E-66 bis E-71
- Projektseite auf GitHub Pages (https://andrez1971.github.io/E.L.L.A.-Defence-Endpoint/), Deutsch/Englisch, ohne externe Ressourcen; jede Zahl wird vor dem Veröffentlichen gegen das Repository geprüft (`tools/check-site.py`)

### Lauf 1 (Hyper-V-VM, Windows 11 Enterprise 25H2, 2026-10-03)

- Vollständiger Durchlauf Phase A bis F, Protokoll und Rohdaten unter `conformance/runs/2026-10-03-Enterprise25H2-26200.9550-HyperV/`. Enforce-Modus 15/15, Rücknahme stellt den Ausgangszustand her, Unterschiede sind gemessen und als Abweichungen geführt.
- **Befund, noch offen:** Windows Update, Defender-Signaturen und BITS sind unter Enforce nicht erreichbar, weil dienstbezogene Erlaubnisregeln für `wuauserv` und `BITS` nicht greifen (E-73, E-74). Nach `Restore` und Neustart kam der EDEP-Zustand einmal zurück, nicht reproduziert (E-76).
- **Korrigiert und in der VM nachgemessen (E-80, E-81):** `Test-EdepL1` meldete TEL-04 unter „ausgehend Block“ mit PASS, obwohl Updates nicht erreichbar sind; jetzt WARN ohne Messung und FAIL mit `-ProbeUpdates`, wenn die Update-Suche scheitert. `Install-EdepL1 -DeployAppControlAudit` legte je Aufruf eine weitere App-Control-Richtlinie an; jetzt wird die vorherige entfernt. `Restore-EdepL1` warnt nicht mehr bei bereits entfernten Richtlinien. Zehn neue Einheitentests (23 insgesamt).
- Spezifikation: B-01 auf den gemessenen Stand gebracht, Hinweise bei TEL-04, ID-05 und OPS-01.
- Anleitung: Ausführungsrichtlinie, `J` statt `y` auf deutschem Windows, sechs Rückfragen, bekannte Grenze von `-Enforce` im README; Testplan um Hinweise aus Lauf 1 ergänzt.
- Nachweise E-72 bis E-79, vier Einträge in der Fehlerliste; E-71 jetzt gemessen.

### Lauf 2 (Hyper-V-VM, Windows 11 Pro 26H2, Build 26300, 2026-10-03)

- Zweiter vollständiger Durchlauf (Phasen A bis E) mit den korrigierten Skripten aus dem Nachtest von Lauf 1, Protokoll und Rohdaten unter `conformance/runs/2026-10-03-Pro26H2-26300.9457-HyperV/`. Enforce 15/15 mit TEL-01 und TEL-04 als WARN; Edge kommt unter Enforce durch (erstmals gemessen); die Befunde zu Updates und BITS treten auch auf Pro auf (E-82, E-83).
- Diagnose der Dienstregeln mit Filterdump und Netzwerkmitschnitt: Der Filter ist wohlgeformt; der Update-Client verbindet mit dem Token des aufrufenden Benutzers ohne Dienst-SID (E-84). Außerdem: `MpDefenderCoreService.exe` wird unter Enforce blockiert (E-85), die Wirkung der DiagTrack-Sperre ist ungemessen (E-86).
- **Neu: `Install-EdepL1.ps1 -AllowWindowsUpdate`** (DD-13): Regeln „Programm `svchost.exe` + Update-Domains“ (Dynamic Keywords), Netzwerkschutz im Audit-Modus, in der VM nachgemessen (E-88). `Restore-EdepL1` entfernt die Schlüsselwörter und stellt den Netzwerkschutz zurück (E-90, im Nachtest gefundener und behobener Fehler). `Test-EdepL1`: EDEP-TEL-04 meldet unter Enforce ohne die Option FAIL (14/15), mit der Option WARN. 13 weitere Einheitentests (40 insgesamt). Ungemessen: Neustart, Updateinstallation, Defender-Signaturen, fremder Virenschutz (E-89).
- **Korrektur:** Das zuvor als „nicht gelernt“ beschriebene CDN-Ziel wird gelernt, aber mit einigen Sekunden Verzögerung nach dem ersten Verbindungsversuch (DNS-Protokoll mit CNAME-Ketten, BITS-Versuch 1 scheitert, 2 und 3 gelingen). Die Option wirkt daher mit Wiederholungen, nicht bei sofortigen Einzelversuchen.
- **E-76 nachgemessen** ([Lauf 4](conformance/runs/2026-10-04-Enterprise25H2-26200.9550-HyperV-Lauf4/run.md)): Nach einem harten Neustart direkt nach `Restore-EdepL1` kam in 3 von 6 gültigen Fällen der Telemetriewert zurück. `Restore-EdepL1` schreibt jetzt Registrierung (`SOFTWARE`, `SYSTEM`, `HKLM`) und Dateisystem auf den Datenträger (`Invoke-EdepFlushRegistry`, `SECURITY` und `SAM` optional); damit 0 von 6. Die früheren umfassenderen Vorfälle sind weiter ungeklärt. Das Konformitätsskript lief erstmals als Administrator fehlerfrei (Schritt 2); TEL-02-WARN, TEL-04-Hinweis und LOG-01-WARN in der VM gesehen. 3 neue Einheitentests (64 insgesamt). Edge: gestartet, Laden nicht bestätigt.
- **`conformance/Test-EdepConformance.ps1`:** ein Aufruf für Dritte (ändert nichts): Integrität (SHA256SUMS und Signatur), die 15 L1-Prüfungen, Audit, mit `-Probe` zusätzlich Update-Messung und Einheitentests; Protokoll als JSON (`schemaVersion` 1) mit `notRun` für alle nicht ausgeführten Tests und Exit-Codes 0, 1, 2. Hilfsfunktionen in `conformance/EdepConformance.Common.ps1`; 17 neue Einheitentests (61 insgesamt); Rauchtest in der CI. Kein Konformitätsnachweis; die Stufe „Destructive“ (Install, Enforce, Umgehungen, Restore in einer Test-VM) ist noch nicht umgesetzt.
- **Signierte Releases (Vorbereitung):** `docs/SIGNING.md`, `tools/make-checksums.py` (SHA256SUMS aus dem Git-Archiv, byteweise identisch mit dem GitHub-ZIP des Tags, am Tag `0.1.0-draft.2` mit 97 Dateien geprüft), `allowed_signers`, `.gitattributes` (Prüfsummen und Signatur werden nie umgewandelt). Eigener ED25519-Schlüssel nur für Releases, bei GitHub als „Signing Key“ hinterlegt. Die Skripte sind weiterhin **nicht** Authenticode-signiert.
- **`Test-EdepConformance.ps1 -Destructive -ConfirmDestructive`:** Stufe für eine Test-VM (`conformance/EdepConformance.Destructive.ps1`): Fingerabdruck, Install im Audit- und Enforce-Modus, Umgehungstests (`curl.exe`, umbenannte Kopie, BITS, Authenticated-Bypass-Regel, uneingeschränkte Regel, beschreibbarer Pfad), Restore und Fingerabdruck-Vergleich; Abschnitt `destructive` im Protokoll, ausgeführte Tests verschwinden aus `notRun`. Verweigert den Lauf ohne Adminrechte, ohne erkannte VM, ohne Bestätigung oder bei angewendetem EDEP; ein Abbruch löst Restore aus. 13 neue Einheitentests (77 insgesamt). **In der Enterprise-VM gelaufen** ([Protokoll](conformance/runs/2026-10-04-Enterprise25H2-26200.9550-HyperV-Destructive/run.md)): Lauf 1 12 von 13 Schritten (ein Fehler der Stufe: Testdatei für den Pfad-Test nicht angelegt), nach der Korrektur **13 von 13**, Rücknahme mit identischem Fingerabdruck, auch nach ordentlichem Neustart. Auf Pro noch nicht gelaufen.
- **SPEC 3.6 „Bekannte Einschränkungen“ als Tabelle** (Punkt, gemessener Stand, offen oder nicht geprüft): Rücknahme (E-76), Updates unter Enforce, Defender-Komponenten (E-85), DiagTrack-Sperre (E-86), SYSTEM-Scans (E-87), App Control, Skripte (nicht Authenticode-signiert), Umgebungen (Windows 10 nie gemessen, Home, Server, andere Sprachen, fremder Virenschutz, DoH), Edge. README verweist darauf.
- **E-86 auf Pro nachgemessen** ([Messprotokoll](conformance/runs/2026-10-04-Pro26H2-26300.9457-HyperV-E86/run.md)): Die Dienstregel hat `DiagTrack` auch auf Windows 11 Pro 26H2 nicht blockiert (drei Verbindungen trotz Regel, keine blockierte); der niedrigste Telemetrie-Level senkt die Verbindungen nicht erkennbar; `dmwappushservice` war gestoppt. Der geänderte `Restore-EdepL1` lief dort ohne Fehlalarm zu `SECURITY`. Kleine Messung, eine VM.
- **E-86 gemessen** (Enterprise 25H2, [Messprotokoll](conformance/runs/2026-10-03-Enterprise25H2-26200.9550-HyperV-E86/run.md)): Die Dienstregel aus EDEP-TEL-02 hat `DiagTrack` nicht blockiert (eine erlaubte Verbindung trotz Regel, keine blockierte). `Test-EdepL1` meldet EDEP-TEL-02 deshalb als **WARN** statt PASS; SPEC, BSI-MAPPING, TESTPLAN und Register angepasst. Kleine Messung, eine VM.
- `Test-EdepL1` (EDEP-LOG-01): Firewall-Protokoll mit Größenlimit unter 16.384 KB gibt **WARN** (Empfehlung BSI SiSyPHuS AP10, `Install-EdepL1` setzt 16.384 KB); 4 Einheitentests (44 insgesamt).
- **`docs/BSI-MAPPING.md` (Entwurf):** Zuordnung zu IT-Grundschutz-Kompendium Edition 2023 (SYS.2.2.3, SYS.2.1, OPS.1.1.3, OPS.1.1.5) nach dem Originaltext, mit Hashes der gelesenen PDFs. Zwei Spannungen benannt (Updates unter Enforce, unsignierte Skripte). SiSyPHuS AP4, AP10, AP11 (Windows 10) zugeordnet: DiagTrack-Dienstregel entspricht der BSI-Empfehlung, Firewall-Protokollierung stimmt überein, Signierung der Anwendungssteuerung fehlt in L1. NET.3.2 als nicht anwendbar eingeordnet (netzbasierte Firewalls, keine Anwendungsfilterung); Edition 2023 war am 2026-10-03 die einzige gelistete; keine BSI-Bestätigung.
- **SPEC 3.5 „Betriebsmodell: Aktualisierungen unter ausgehender Sperre“** (zentraler Update-Server, Wartungsfenster oder `-AllowWindowsUpdate` mit Stand der Messung; ohne festgelegten Weg ist Enforce nicht empfohlen) und **SPEC 3.6 „Bekannte Einschränkungen“** (E-76, E-85 bis E-87, Ungemessenes). `Test-EdepL1` (TEL-04) und `Install-EdepL1` (Hinweis unter Enforce) nennen jetzt eine Handlungsanweisung mit Verweis auf SPEC 3.5. OPS-01: E-76 jetzt „zwei von sechs gültigen Versuchen“.
- **Dokumentation:** README, SPEC TEL-04, DD-13 und Roadmap nennen jetzt ausdrücklich: Enforce nur mit definiertem Update-Weg empfohlen, `-AllowWindowsUpdate` nicht zuverlässig, Suche nach einer Umgehung beendet.
- **Lauf 3** (Enterprise 25H2, Tag `0.1.0-draft.2`, [Protokoll](conformance/runs/2026-10-03-Enterprise25H2-26200.9550-HyperV-Lauf3/run.md)): Audit 14/15, Enforce mit `-AllowWindowsUpdate` 15/15, Restore und Neustart stellen den Ausgangszustand her (sauberer Neustart, kein Vorfall E-76). **Die Update-Erreichbarkeit war nicht zuverlässig:** im ersten Messblock scheiterten Suche, BITS und `Update-MpSignature` in 9 von 9 Versuchen, später gelang die Suche ab dem zweiten Versuch; Ursache unbekannt. Edge-Antwort blieb aus (nicht gemessen).
- Messung nach Neustart mit leerem Cache (E-89): Suche gelingt ab dem zweiten Versuch; BITS zu `ctldl.windowsupdate.com` scheitert, weil `146.75.122.172:80` trotz passendem Namen nicht gelernt wird. Die Option ist **teilweise wirksam**.
- Messungen zu E-89: Defender-Signaturupdates sind mit `-AllowWindowsUpdate` **nicht gelöst** (`Update-MpSignature` scheitert, Signaturstand unverändert; zusätzliche Defender-Domains aus Microsofts Liste ändern nichts); die Wildcard-Regeln lernen Adressen korrekt, das Race beim ersten Versuch bleibt. `Restore-EdepL1` warnt jetzt mit dem manuellen Befehl, wenn es den Netzwerkschutz nicht zurückstellen kann.
- Lösungsversuch Update-Erreichbarkeit: Regeln „Programm `svchost.exe` + Update-Domains“ (Dynamic Keywords) lassen Suche und BITS zu Microsoft unter Enforce durch und halten `example.org` gesperrt; setzt den Netzwerkschutz voraus (E-88). Noch nicht im Installer, offene Punkte E-89.
- Kontrollmessung auf Pro bei aktiver Pause: Die Update-Suche gelingt ohne EDEP und scheitert mit EDEP (`wuauserv` blockiert); die Pause ist nicht die Ursache.
- Der Neustart-Vorfall aus Lauf 1 trat auf Pro erneut auf (zweimal in fünf Versuchen), Ursache weiter offen (E-76).

### Offen (aus dem ersten Durchlauf, Windows-Sandbox, 2026-10-02)

- Abweichung 11 (BITS im Enforce-Modus blockiert): in Lauf 1 in der VM bestätigt, B-01 korrigiert; Ursache weiter offen (E-71, E-73).
- Abweichung 12 (Regelanzahl nach der Rücknahme): in der VM **nicht** aufgetreten, die Zahlen stimmen exakt; damit spricht alles für eine Eigenschaft des Sandbox-Images.
- App Control, Defender und Windows Update, in der Sandbox nicht prüfbar, wurden in Lauf 1 gemessen (siehe oben).

### Korrigiert

- **`Install-EdepL1.ps1`:** brach im ersten Schritt ab (`auditpol`: „Falscher Parameter“), weil `/file:(Join-Path …)` in Windows PowerShell 5.1 in zwei Argumente zerfällt. Argument in Anführungszeichen; neue CI-Sperre gegen dieses Muster. Entdeckt im ersten Durchlauf (Windows-Sandbox).
- **EDEP-NET-10:** `Delete` an der Laufwerkswurzel wird nicht mehr als Gefahr gewertet (Falsch-Positiv; der Installer hätte `-AllowProgram` abgelehnt).
- **EDEP-NET-03:** prüft zusätzlich die Wirkung: Eine uneingeschränkte ausgehende Erlaubnisregel hebt die Standardsperre auf und lässt NET-03 fehlschlagen. Neue Umgehung B-08.
- Testplan: falsche Erwartungen korrigiert (TEL-01, NET-10, OPS-01), Eigenschaften der Windows-Sandbox gemessen und dokumentiert.
- **EDEP-NET-08:** Boot-Time- und persistente Filter sind getrennte Sätze; die Flags sind laut
  Microsoft nicht kombinierbar. Provider muss an einen auto-startenden Dienst gebunden sein.
- **EDEP-NET-07:** Sublayer mit höchstem Gewicht; hard permit in höherem Sublayer als Risiko benannt.
- **EDEP-NET-02:** Stealth-Prüfung berücksichtigt den Richtlinienschlüssel `PrivateProfile`.
- **EDEP-NET-04:** Ausnahme „Authenticated Bypass“ benannt und geprüft.
- **EDEP-TEL-03:** verlangt zusätzlich `EnableActivityFeed = 0` (Erfassung abschalten, nicht nur den Upload), gemäß Microsoft-Empfehlung (Q-26).
- **EDEP-TEL-01/-02:** Editionsgrenzen, Microsoft-Empfehlung und Dienst-SID-Typ belegt bzw. geprüft.

### Geändert

- Bezug zur E.L.L.A. Directive auf „inspiriert von“ reduziert; EDEP ist eigenständig.

## [0.0.1] – 2026-09-30

Tag „30.09.2026 21:30 Uhr gestartet“. Erster Entwurf: SPEC 0.1.0, L1-Skripte,
Konformitätskatalog, Richtlinienschema, Designentscheidungen.
