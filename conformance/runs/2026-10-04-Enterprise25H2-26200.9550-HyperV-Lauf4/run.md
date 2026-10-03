# Testprotokoll Lauf 4: Konformitätsskript als Administrator, Kleinkram, Rücknahme-Vorfall (E-76)

**Stand: gemessen 2026-10-03 23:59 bis 2026-10-04 01:22 (Uhr der VM). Enterprise-VM, Stand `e817c33` (Schritte 2 und 3); ab Runde 3 von E-76 mit geändertem `Restore-EdepL1.ps1` und `EdepL1.Common.ps1` (Flush).** Vorlage: [TEMPLATE.md](../TEMPLATE.md). Vorheriger Lauf: [Lauf 3](../2026-10-03-Enterprise25H2-26200.9550-HyperV-Lauf3/run.md). Messwerte wörtlich aus der Konsole; Abweichungen werden geführt, nicht angepasst. Rohdaten in [beweise/](beweise/).

## Umgebung

| | |
|---|---|
| VM | Hyper-V `EDEP-Test-Ent`, Windows 11 Enterprise Evaluation 25H2, Build 26200.9550, Computername `DESKTOP-QKILAOK`, Konto `test` (lokaler Administrator) |
| Stand | Commit `e817c33` (nach Lauf 3, ohne Tag), 124 Dateien per PowerShell Direct nach `C:\edep-run4` kopiert; für E-76 Runde 3 zusätzlich `Restore-EdepL1.ps1` und `EdepL1.Common.ps1` mit `Invoke-EdepFlushRegistry` (siehe unten) |
| Defender | aktiv, Netzwerkschutz `0` im Ausgangszustand |
| Prüfpunkt | `vor-e76-2026-10-04` (Hyper-V), vor den E-76-Läufen angelegt |

## Schritt 2: Konformitätsskript als Administrator (Ausgangszustand, `-Probe -SkipIntegrity`)

| Nr. | Messwert (wörtlich) | Einordnung |
|---|---|---|
| S2-1 | `EDEP-Regeln vorher: 0 (erwartet 0); Netzwerkschutz: 0 (erwartet 0)` | Ausgangszustand wie erwartet |
| S2-2 | L1 **7 von 15**: PASS NET-01, NET-02, NET-10 („16 freigegebene Programmpfade“), TEL-04, LOG-02, LOG-06 und OPS-01 („Sicherung vorhanden“); FAIL NET-03, NET-04, NET-05, ID-01, TEL-01, TEL-02, TEL-03, LOG-01 | wie erwartet; OPS-01 PASS, weil die Sicherungen aus Lauf 3 liegen bleiben |
| S2-3 | `Umgebung: EnterpriseEval 26200.9550, Admin=True, VM=True`; `Integrität: SKIPPED / SKIPPED`; `L1: 7 von 15, Audit: 41 (D)`; `Einheitentests: ran=True bestanden=61 fehlgeschlagen=0`; `notRun: 19 Tests`; `Exit-Code: 1` | **erster Lauf des Skripts als Administrator, ohne Fehler**; Protokoll `edep-conformance-DESKTOP-QKILAOK-20261003-235949.json` |

## Schritt 3: Kleinkram (Edge, TEL-02, LOG-01, Exit-Code 2)

Install mit `-Enforce -DeployAppControlAudit -AllowWindowsUpdate -AllowProgram <Edge>`.

| Nr. | Messwert (wörtlich) | Einordnung |
|---|---|---|
| S3-1 | `EDEP-TEL-02  Blockregeln und Dienst-SID-Typ in Ordnung (DiagTrack, dmwappushservice), Wirkung nicht belegt: DiagTrack verband in der Messung trotz Regel (E-86)` (WARN); `EDEP-TEL-04 … Wirkung nicht gemessen. Messen: .\Test-EdepL1.ps1 -ProbeUpdates. Betrieb: Enforce nur mit definiertem Update-Weg (SPEC 3.5)` (WARN); `EDEP 0.1.0 L1 — geprüft 2026-10-04 — 15/15 erfüllt` | neue Meldungen mit Handlungsanweisung **gesehen**; 15/15 mit zwei WARN |
| S3-2 | Public-Profil auf 4096 KB: `WARN    EDEP-LOG-01  Firewall-Log und Ereignis 5157 aktiv, Größenlimit unter 16.384 KB (Empfehlung BSI SiSyPHuS AP10): Public`, Summe weiter `15/15`; nach Zurücksetzen auf 16384: `PASS    EDEP-LOG-01` | LOG-01-WARN **gesehen** |
| S3-3 | `Test-EdepConformance.ps1 -SkipIntegrity` unter Enforce: `Ergebnis unvollständig (UNKNOWN, Integrität nicht prüfbar oder nur Zeilenenden abweichend).`, `Exit-Code: 2` | wie erwartet (kein FAIL, aber Integrität nicht geprüft) |
| S3-4 | Edge: Der Tester meldete „edge wurde erfolgreich gestartet“. Ob die Seite `example.org` geladen hat und ob das für beide Starts (Ausgangszustand und Enforce) galt, wurde **nicht** angegeben | **R-A7 und R-C6: Edge gestartet, Laden der Seite nicht bestätigt** |
| S3-6 | Protokoll `edep-conformance-DESKTOP-QKILAOK-20261004-000222.json` (Rohdatei): `l1.passed` 15 von 15, WARN bei `EDEP-TEL-02` und `EDEP-TEL-04`, Audit **83** unter Enforce, `verdict.exitCode` 2, `notRun` 19, `schemaVersion` 1 | die Rohdatei bestätigt die Konsolenausgabe |
| S3-5 | Rücknahme: „Wiederherstellung abgeschlossen“; `Vergleich mit vorher.json (leer = identisch):` ohne Zeilen | Ausgangszustand wiederhergestellt |

## Schritt 4: E-76, Rücknahme und Neustart

Ablauf je Durchlauf, vom Host über PowerShell Direct gesteuert: `Install-EdepL1 -Enforce -DeployAppControlAudit` (Runde 2 teils mit `-AllowWindowsUpdate -AllowProgram <Edge>`), `Restore-EdepL1`, Zustand lesen (Firewall-Standardaktion je Profil, Zahl der EDEP-Regeln, `AllowTelemetry`, Zahl der EDEP-App-Control-Richtlinien), Wartezeit, Neustart (**ordentlich**: `Restart-Computer -Force` im Gast; **hart**: `Stop-VM -TurnOff` und `Start-VM`), nach dem Start Zustand erneut lesen. **Vorfall** heißt: Der Zustand nach dem Neustart weicht von dem nach der Rücknahme ab. Rohdaten: `e76-20261004-002018.json` (Runde 1), `e76-runde2-20261004-003117.json` (Runde 2), `e76-runde3-flush-20261004-012204.json` (Runde 3).

| Runde | Durchlauf | Neustart, Wartezeit nach Restore | Ergebnis |
|---|---|---|---|
| 1 | 1 | ordentlich, 0 s | sauber |
| 1 | 2 | ordentlich, 30 s | sauber |
| 1 | 3 | hart, 0 s | sauber (Ereignisse 41 und 6008) |
| 1 | 4 | hart, 5 s | **ungültig** (Messfehler, Zustand nach dem Start nicht lesbar) |
| 1 | 5 | hart, 30 s | **ungültig** (EDEP wurde nicht angewendet, Sitzung abgebrochen) |
| 1 | 6 | ordentlich, 0 s | sauber |
| 1 | 7 | hart, 0 s | sauber |
| 1 | 8 | hart, 5 s | sauber |
| 2 | A | hart, 5 s | **Vorfall:** `AllowTelemetry` = `0` zurück, Firewall, Regeln und App Control zurückgenommen |
| 2 | B | hart, 30 s | **Vorfall:** wie A |
| 2 | C | hart, 0 s (volle Install-Fassung) | **Vorfall:** wie A |
| 2 | D | ordentlich, 0 s (volle Fassung) | sauber |
| 3 (mit Flush) | 1 bis 6 | hart, je 0, 0, 5, 5, 30, 30 s | **alle sechs sauber** |

**Befund:**

- **Teilweise reproduziert.** Nach einem **harten** Neustart direkt nach `Restore-EdepL1` kam in drei von sechs gültigen Fällen (Runde 1 und 2) der **Telemetrie-Richtlinienwert** `AllowTelemetry = 0` zurück. Zurückgenommene Firewall und App Control blieben zurückgenommen. Nach **ordentlichen** Neustarts trat es in vier Fällen nie auf.
- **Zufall nicht ausgeschlossen:** Runde 1 war ohne Flush dreimal sauber, Runde 2 dreimal nicht. Die Runden liefen nacheinander, nicht gemischt.
- **Gegenmaßnahme:** `Restore-EdepL1` schreibt jetzt am Ende die Registrierungs-Hives (`RegistryKey.Flush()` für `SOFTWARE`, `SYSTEM`, `HKLM`) und das Dateisystem (`Write-VolumeCache`) auf den Datenträger. Mit dieser Änderung traten in **sechs von sechs** harten Neustarts (0, 0, 5, 5, 30, 30 s) keine Vorfälle auf. Wären Vorfälle ohne Flush gleich häufig wie mit (3 von 6), wäre „0 von 6“ mit etwa 2 % Wahrscheinlichkeit zufällig.
- **Mechanismus nicht bewiesen:** Die Erklärung „verzögertes Schreiben der Registrierung“ ist eine Vermutung, die zu den Daten passt. Sie erklärt nicht die **früheren** Vorfälle aus Lauf 1 und 2 (dort kamen auch Firewall und App Control zurück); deren Ursache bleibt **ungeklärt**.
- **Fehlalarm in Runde 3:** Jede Rücknahme meldete „Rücknahme konnte nicht vollständig auf den Datenträger geschrieben werden: SECURITY“. Der Hive `SECURITY` ist nur mit SYSTEM-Rechten schreibbar. Danach geändert: `SECURITY` und `SAM` gelten als optional und erzeugen keine Warnung mehr (Einheitentest). Dieser Stand wurde nicht noch einmal in der VM gemessen.

## Abweichungen und Fehler der Messung

| Nr. | Was weicht ab | Befund |
|---|---|---|
| 1 | E-76 Runde 1, Durchläufe 4 und 5 | Messfehler meines Skripts: Es hielt den Gast zu früh für bereit und zählte leere Messwerte als Vorfall. Beide Durchläufe sind **ungültig** und zählen nicht |
| 2 | Anmeldung am Gast schlug fehl (`Die Anmeldeinformationen sind ungültig`) | Mein erster Wiederholungsblock versuchte 15 Minuten lang alle 10 Sekunden die Anmeldung (rund 90 Fehlversuche; Richtlinie: Sperre nach 10 Versuchen für 10 Minuten). Ursache des allerersten Fehlschlags ungeklärt. Gelöst mit einem neuen Kennwort für das Konto; Blöcke brechen jetzt beim ersten Fehler ab |
| 3 | Edge | siehe S3-4: Laden der Seite nicht bestätigt |
| 4 | Nicht gemessen | Integrität PASS im Lauf (nur mit signiertem Release); Stufe „Destructive“ des Konformitätsskripts; E-86 auf Pro; E-85, E-87 |

## Fazit

- Das Konformitätsskript läuft als Administrator ohne Fehler; Exit-Codes 1 und 2 verhalten sich wie vorgesehen.
- TEL-02-WARN, TEL-04-Hinweis und LOG-01-WARN erscheinen wie geplant.
- E-76: Ein **harter** Neustart direkt nach der Rücknahme konnte den Telemetriewert zurückbringen; eine Flush-Änderung an `Restore-EdepL1` verhinderte das in sechs von sechs Fällen. **Die früheren, umfassenderen Vorfälle sind weiter ungeklärt.** Ordentliche Neustarts waren in allen Fällen sauber.
- Kein Konformitätsnachweis.
