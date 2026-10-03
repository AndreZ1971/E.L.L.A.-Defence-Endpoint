# Messprotokoll E-86: Wirkung der DiagTrack-Dienstregel (Enterprise 25H2, nach Lauf 3)

**Stand: gemessen 2026-10-03, 22:40 bis 22:49 (Uhr der VM). Kleine Messung, ein Durchlauf, eine VM.** Gleiche VM wie [Lauf 3](../2026-10-03-Enterprise25H2-26200.9550-HyperV-Lauf3/run.md) (Windows 11 Enterprise Evaluation 25H2, Build 26200.9550, Skripte des Tags `0.1.0-draft.2`), im Ausgangszustand nach Lauf 3 (keine EDEP-Regeln, Telemetrie-Richtlinie nicht gesetzt). Die Messwerte sind wörtlich aus der Konsole übernommen; die Rohdaten (`transcript-e86.txt`, `nach-e86.json`) liegen in [beweise/](beweise/). Der Fingerabdruck nach der Rücknahme (`nach-e86.json`) ist inhaltlich identisch mit `vorher.json` aus Lauf 3 (ohne Zeitstempel verglichen).

**Frage:** Greift die Sperrregel EDEP-TEL-02 (`New-NetFirewallRule -Service DiagTrack -Action Block`, entspricht der Empfehlung in SiSyPHuS AP4, Abschnitt 2.3) auf Windows 11 gegen den Prozess des Dienstes `DiagTrack`?

**Verfahren:** Überwachung „Filterplattformverbindung“ auf Erfolg und Fehler (5156 und 5157). Pro Phase `DiagTrack` neu starten, 8 mal 30 Sekunden warten und die Ereignisse zählen, deren Prozess-ID die des `DiagTrack`-Dienstes ist (ohne Loopback und Multicast). Phase 1 ohne EDEP, Phase 2 nach `Install-EdepL1.ps1 -Confirm:$false` (Audit-Modus, enthält die Dienstregel). Danach Rücknahme.

**Erwartung vorab:** H1 Regel wirkt (Phase 2: 5157, kein 5156). H2 Regel wirkt nicht (Phase 2: weiter 5156). Leer, wenn schon Phase 1 keine Verbindung zeigt.

| Nr. | Messwert (wörtlich) | Einordnung |
| --- | --- | --- |
| M-1 | `Edition: EnterpriseEval`; `AllowTelemetry (Richtlinie):  (leer = nicht gesetzt)`; `EDEP-Regeln: 0 (erwartet 0)` | Ausgangslage wie erwartet |
| M-2 | Phase 1: `DiagTrack Status: Running, PID 5472`; nach 120 s `erlaubt (5156) 2, blockiert (5157) 0`; Ziele `5156, 40.79.167.9:443` und `5156, 52.168.117.171:443` | `DiagTrack` baut ohne EDEP Verbindungen auf |
| M-3 | Phase 2: `Dienstregel(n) für DiagTrack: EDEP L1 - Telemetrie DiagTrack (EDEP-TEL-02)`; `PASS    EDEP-TEL-02  Ausgehend blockiert (Dienst-SID wirksam): DiagTrack, dmwappushservice` | Regel vorhanden, der Test bestätigt Regel und SID-Typ |
| M-4 | Phase 2: `DiagTrack Status: Running, PID 452`; nach 150 s `erlaubt (5156) 1, blockiert (5157) 0`; Ziel `5156, 51.132.193.109:443` (bis 240 s unverändert) | **Verbindung trotz Regel erlaubt, keine blockierte Verbindung** |
| M-5 | Prüfung danach: `DiagTrack-PID: 452`; `Dienste in diesem Prozess: DiagTrack`; `SERVICE_SID_TYPE:  UNRESTRICTED` | Die Verbindung stammt aus einem Prozess, der nur `DiagTrack` hostet; die Regel hat den richtigen SID-Typ |
| M-6 | `Appraiser nicht startbar: Das System kann die angegebene Datei nicht finden.` (beide Phasen) | Der Aufgabenplanungs-Eintrag existiert auf diesem Build nicht; die Verbindungen entstanden durch den Neustart des Dienstes |
| M-7 | Rücknahme: „Wiederherstellung abgeschlossen“; Fingerabdruck-Vergleich mit `vorher.json` leer; Überwachungsrichtlinie aus der eigenen Sicherung wiederhergestellt | Ausgangszustand wiederhergestellt |

**Ergebnis:** **H2 stützt sich.** In Phase 2 verband der `DiagTrack`-Prozess (PID 452, hostet nur diesen Dienst) zu `51.132.193.109:443`, obwohl die Dienstregel galt; es gab keine blockierte Verbindung. Das passt zum Mitschnitt aus [Lauf 2](../2026-10-03-Pro26H2-26300.9457-HyperV/run.md), D-4 (Benutzer-Token ohne Dienst-SID), und zu [E-84](../../../docs/EVIDENCE.md).

**Grenzen:**

- Es sind sehr wenige Verbindungen (2 in Phase 1, 1 in Phase 2), ein Durchlauf, eine VM, eine Edition. Das Ziel in Phase 2 war ein anderes als in Phase 1; Telemetrie-Ziele wechseln.
- Nicht gemessen: ob die Regel andere Verbindungen des Dienstes blockiert, die Wirkung für `dmwappushservice`, das Verhalten auf Pro im Audit-Modus und bei Telemetrie-Level 0 (dort sendet `DiagTrack` laut BSI-Test nicht).
- Das Ergebnis betrifft die **Dienstregel**. Eine Programmregel für `svchost.exe` oder das Abschalten des Dienstes (SiSyPHuS AP4, Abschnitt 2.1) wurde nicht gemessen.

**Folgen:** `Test-EdepL1` meldet EDEP-TEL-02 jetzt als **WARN** („Wirkung nicht belegt“) statt PASS. SPEC EDEP-TEL-02, SPEC 3.6, BSI-MAPPING (SYS.2.2.3.A25, AP4 Abschnitt 2.3) und das Register E-86 sind angepasst.
