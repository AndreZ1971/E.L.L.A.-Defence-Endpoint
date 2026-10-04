# Messprotokoll E-86 auf Windows 11 Pro: DiagTrack-Dienstregel und Telemetrie-Level

**Stand: gemessen 2026-10-04, 19:25 bis 19:40 (Uhr der VM). Kleine Messung, ein Durchlauf, eine VM.** Hyper-V-VM `EDEP-Test-Pro`, Windows 11 **Pro** 26H2, Build 26300.9457, Computername `TEST`, Konto `test1`, Stand `2bc29e1` (mit dem geänderten `Restore-EdepL1`). Gegenstück zur Messung auf Enterprise: [Messprotokoll E-86 Enterprise](../2026-10-03-Enterprise25H2-26200.9550-HyperV-E86/run.md). Rohdaten in [beweise/](beweise/).

**Fragen:** (1) Greift die Dienstregel aus EDEP-TEL-02 gegen den Prozess von `DiagTrack` auch auf Pro? (2) Senkt der niedrigste Telemetrie-Level die Verbindungen? (3) Verbindet `dmwappushservice`?

**Verfahren:** Überwachung „Filterplattformverbindung“ auf Erfolg und Fehler (5156 und 5157). Pro Phase `DiagTrack` neu starten, 10 mal 30 Sekunden warten und die Ereignisse zählen, deren Prozess-ID die des `DiagTrack`-Dienstes (und von `dmwappushservice`, falls sie läuft) ist (ohne Loopback und Multicast). **P1** ohne EDEP und ohne Richtlinie; **P2** nur die Richtlinie `AllowTelemetry=0` (auf Pro wirkt der niedrigste Level, 1 „Required“), **keine** Firewallregel; **P3** nach `Install-EdepL1.ps1` im Audit-Modus (Richtlinie und Dienstregel). Danach Rücknahme und Fingerabdruck-Vergleich.

**Erwartung vorab:** P1 zeigt Verbindungen. P3: H1 Regel wirkt (5157, kein 5156) oder H2 Regel wirkt nicht (weiter 5156, wie auf Enterprise). P2: unbekannt.

| Nr. | Messwert (wörtlich) | Einordnung |
|---|---|---|
| M-1 | `Edition Professional, Build 26300.9457; AllowTelemetry (Richtlinie): '' (leer = nicht gesetzt); EDEP-Regeln: 0 (erwartet 0)` | Ausgangslage wie erwartet |
| M-2 | **P1** (PID 5732, `Dienste im Prozess: DiagTrack`): nach 300 s `erlaubt (5156) 2, blockiert (5157) 0`; Ziele `4.150.223.103:443`, `4.150.223.115:443` | `DiagTrack` verbindet ohne EDEP (beide Verbindungen erst im letzten Fenster, 270 bis 300 s) |
| M-3 | **P2** (PID 3496): nach 300 s `erlaubt (5156) 1, blockiert (5157) 0`; Ziel `20.184.175.5:443` (erst nach 240 s) | Mit dem niedrigsten Level (Required) ist **keine erkennbare Senkung** zu sehen (2 gegen 1 Verbindung) |
| M-4 | P3: `Dienstregel(n) für DiagTrack: EDEP L1 - Telemetrie DiagTrack (EDEP-TEL-02)`; `WARN    EDEP-TEL-01  AllowTelemetry=0, wirksam auf 'Professional': 1 (Required) — niedrigste Stufe dieser Edition`; `WARN    EDEP-TEL-02  Blockregeln und Dienst-SID-Typ in Ordnung (DiagTrack, dmwappushservice), Wirkung nicht belegt: …` | Regel vorhanden |
| M-5 | **P3** (PID 3192, `Dienste im Prozess: DiagTrack`): nach 210 s `erlaubt (5156) 2`, nach 240 s `3`, bis 300 s unverändert, **`blockiert (5157) 0`**; Ziele `48.209.133.15:443`, `40.79.150.125:443`, `40.79.167.10:443` | **Drei Verbindungen trotz Regel, keine blockierte** |
| M-6 | `dmwappushservice: Stopped, PID 0` in allen drei Phasen; Zähler `0` | Der Dienst war gestoppt, **keine Aussage zur Wirkung der Regel** |
| M-7 | Rücknahme: „Wiederherstellung abgeschlossen“ **ohne** Warnung; `Vergleich mit dem Ausgangszustand (leer = identisch):` ohne Zeilen; `vorher-pro-e86.json` und `nachher-pro-e86.json` inhaltlich identisch (ohne Zeitstempel) | Ausgangszustand wiederhergestellt; **der geänderte `Restore-EdepL1` lief hier zum ersten Mal in einer VM ohne Fehlalarm zu `SECURITY`** |

**Ergebnis:**

- **H2 gilt auch auf Pro:** Mit der Dienstregel verband der `DiagTrack`-Prozess dreimal und keine Verbindung wurde blockiert. Zusammen mit Enterprise (eine Verbindung trotz Regel) ist das auf **zwei Editionen** belegt.
- **Der niedrigste Level senkt die Verbindungen nicht erkennbar** (P1 2, P2 1, P3 3); auf Enterprise verband `DiagTrack` ebenfalls trotz `AllowTelemetry=0`. Die Zahlen sind zu klein und streuen, um einen Unterschied zu zeigen oder auszuschließen.
- **`dmwappushservice`** war in allen Phasen gestoppt und konnte nicht verbinden.

**Grenzen:** Wenige Verbindungen pro Phase (0 bis 3); die meisten erscheinen erst nach 210 bis 300 Sekunden, ein Teil könnte nach dem Fenster liegen. Je ein Durchlauf, je eine VM pro Edition. Nicht gemessen: eine Programmregel für den Prozess oder das Abschalten des Dienstes (SiSyPHuS AP4, Abschnitt 2.1) als Ersatz; `dmwappushservice` im laufenden Zustand; längere Beobachtung.

**Abweichungen:** Der Aufgabenplanungs-Eintrag „Microsoft Compatibility Appraiser“ wurde hier nicht angestoßen (Skript dieses Laufs verzichtete darauf); die Verbindungen entstanden durch den Neustart des Dienstes. Die Anmeldung am Gast erfolgte mit dem Kennwort des Kontos `test1`.
