# Testprotokoll L1-Durchlauf: Hyper-V-VM, Windows 11 Enterprise Evaluation 25H2 (Lauf 3)

**Stand: Lauf 3 abgeschlossen (Phasen A bis F). Erster Lauf auf dem veröffentlichten Stand (Tag `0.1.0-draft.2`) mit der Option `-AllowWindowsUpdate`. Eingeschränkte Aussage, siehe Fazit.** Vorlage: [TEMPLATE.md](../TEMPLATE.md). Plan: [TESTPLAN-L1.md](../../../docs/TESTPLAN-L1.md). Vorherige Läufe: [Lauf 1, Enterprise 25H2](../2026-10-03-Enterprise25H2-26200.9550-HyperV/run.md), [Lauf 2, Pro 26H2](../2026-10-03-Pro26H2-26300.9457-HyperV/run.md).
Messwerte wörtlich; Abweichungen werden geführt, nicht angepasst. Die Rohdaten liegen in [beweise/](beweise/).

## Umgebung

|                        |                                                                                                                                                                                                         |
| ---------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Datum                  | 2026-10-03, ca. 21:16 bis 21:42 (Uhr der VM)                                                                                                                                                            |
| Durchgeführt von       | Andre Zabel, begleitet von Claude                                                                                                                                                                       |
| Umgebung               | Hyper-V-VM `EDEP-Test-Ent` (Computername `DESKTOP-QKILAOK`), Netz „Default Switch“                                                                                                                      |
| Edition und Build (VM) | Windows 11 **Enterprise Evaluation** (`EnterpriseEval`), 25H2, Build 10.0.26200, UBR 9550                                                                                                               |
| Benutzer               | lokales Konto `test`                                                                                                                                                                                    |
| Getesteter Stand       | **Tag `0.1.0-draft.2`**, als ZIP von GitHub geladen; ZIP SHA-256 `90770105D114F90CB285D188ECA7597CE7521C4D402AF1FC782F71129D4C0011`; alle 11 Dateihashes stimmen mit dem Tag überein (`transcript.txt`) |
| Defender               | aktiv, Plattform `4.18.26080.4`, Engine `1.1.26080.3`, Signatur `1.459.536.0` (während des Laufs unverändert)                                                                                           |
| Update-Pause           | in der Registrierung bestätigt: `2026-10-10T19:17:26Z` (alle drei Werte)                                                                                                                                |

## Phase A: Ausgangszustand

| Nr.         | Messwert (wörtlich)                                                                      | Ergebnis  |
| ----------- | ---------------------------------------------------------------------------------------- | --------- |
| R-A1        | `EDEP-Audit DESKTOP-QKILAOK — 41/100 (Stufe D)`, Offen 13, Erfüllt 9                     | OK        |
| R-A2        | `Test-EdepL1` **6/15**: PASS NET-01, NET-02, NET-10 („16 Pfade“), TEL-04, LOG-02, LOG-06 | OK        |
| R-A3        | `vorher.json` erzeugt, Netzwerkschutz `0`                                                | OK        |
| R-A4 / R-A5 | `200` / `200`                                                                            | OK        |
| R-A6        | BITS gelungen                                                                            | OK        |
| R-A7        | Edge im Ausgangszustand: **Antwort nicht gegeben**                                       | **offen** |

## Phase B: Audit-Modus

| Nr.  | Messwert (wörtlich)                                                                                                                                      | Ergebnis |
| ---- | -------------------------------------------------------------------------------------------------------------------------------------------------------- | -------- |
| R-B1 | `-WhatIf` listet die Schritte, „Es wurde nichts geändert“                                                                                                | OK       |
| R-B2 | Fingerabdruck nach `-WhatIf` identisch zu `vorher.json` (Vergleich leer; Hash der Dateien ohne Zeitstempel gleich)                                       | OK       |
| R-B4 | `Test-EdepL1`: **14/15**, nur NET-03 FAIL, **TEL-01 PASS** (`AllowTelemetry=0, wirksam: Security`), TEL-04 PASS                                          | OK       |
| R-B5 | `curl.exe`: `000`                                                                                                                                        | OK       |
| R-B6 | `x.exe` (kopierte `curl.exe` im Temp-Ordner): `200`                                                                                                      | OK       |
| R-B7 | Ereignis 5157 für `\device\harddiskvolume3\windows\system32\curl.exe` (2×, 21:19:58), keines für `x.exe` (Audit-Modus blockiert dessen Verbindung nicht) | OK       |

## Phase C: Enforce mit `-AllowWindowsUpdate` und `-AllowProgram` (Edge)

| Nr.  | Messwert (wörtlich)                                                                                                                                                                                                                                                                                        | Ergebnis  |
| ---- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------- |
| R-C1 | „Lege Update-Domainregeln an (9 Domains, Stand 2026-10-03)“, Hinweis auf die älteste Sicherung `20261003-211947`                                                                                                                                                                                           | OK        |
| R-C2 | **15/15 erfüllt**, TEL-04 = **WARN** („Wirkung nicht gemessen“), NET-03 „149 aktive ausgehende Erlaubnisregeln, keine davon uneingeschränkt“, NET-10 „20 Programmpfade“                                                                                                                                    | OK        |
| R-C3 | `x.exe`: `000`                                                                                                                                                                                                                                                                                             | OK        |
| R-C4 | `curl.exe`: `000`                                                                                                                                                                                                                                                                                          | OK        |
| R-C5 | 5157 mit Pfad für `curl.exe` und `\users\test\appdata\local\temp\x.exe` (je 2×, 21:21:02)                                                                                                                                                                                                                  | OK        |
| R-C6 | Edge unter Enforce: **Antwort nicht gegeben**                                                                                                                                                                                                                                                              | **offen** |
| R-C8 | Dienstregeln: `dmwappushservice, DiagTrack`                                                                                                                                                                                                                                                                | OK        |
| R-C9 | `-AllowProgram` mit beschreibbarem Pfad: Abbruch „… für Nicht-Administratoren änderbar und darf nicht freigegeben werden (EDEP-NET-10)“                                                                                                                                                                    | OK        |
| R-C7 | Update-Suche, Cache zurückgesetzt, 21:21:33 bis 21:22:34: **Suche 1, 2, 3 `FEHLER 0x80072EFD`; BITS (`ctldl.windowsupdate.com`) 1, 2, 3 FEHLER; `Update-MpSignature` 1, 2, 3 `0x80072efd`** (Abstand 5 bis 6 s). `Test-EdepL1 -ProbeUpdates`: TEL-04 **FAIL** „Update-Suche scheitert (0x80072EFD)“, 14/15 | **ABW**   |

## Phase D: Umgehungen

| Nr.  | Messwert (wörtlich)                                                                                                                                                                                                                | Ergebnis            |
| ---- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------- |
| R-D1 | BITS zu `https://example.org` unter Enforce: FEHLER (B-01: blockiert, wie in Sandbox, Enterprise und Pro)                                                                                                                          | OK (Abw. 7)         |
| R-D4 | Regel „Allow, `-Authentication Required`, `-OverrideBlockRules`“ für `curl.exe` ließ sich anlegen; `NET-04` meldet FAIL „Ausgehende Authenticated-Bypass-Regeln heben Blockaden auf: EDEP-Test-B05“; Testregel entfernt, Reste `0` | OK (B-05 bestätigt) |

## Diagnose zur Abweichung (21:33 bis 21:34, `transcript-diag.txt`)

Der Zustand wurde danach **nicht verändert** (Enforce, Regeln und Schlüsselwörter wie in Phase C).

| Nr. | Messwert (wörtlich)                                                                                                                                                                                                                                                 | Einordnung                                                                                       |
| --- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------ |
| D-1 | `EnableNetworkProtection = 2`; `AMRunningMode Normal`; `WinDefend`, `WdNisSvc`, `mpssvc`, `BFE`, `Dnscache`, `wuauserv`, `bits` laufen                                                                                                                              | Voraussetzungen laut Microsoft erfüllt (Defender, Netzwerkschutz Audit)                          |
| D-2 | DNS-Server `172.28.224.1`; `EnableAutoDoh` leer; `Get-DnsClientDohServerAddress` zählt 12 Einträge                                                                                                                                                                  | Die 12 Einträge sind Windows' eingebaute Liste; ob DoH genutzt wird, ist **nicht gemessen**      |
| D-3 | Schlüsselwörter **vor** dem Versuch: alle Adresslisten leer. Die Spalte „Adressen“ meines Befehls zählt auch bei leerer Liste `1` und ist **wertlos** (Fehler im Block)                                                                                             | Wie nach einem Neustart                                                                          |
| D-4 | Namensauflösung: `download.windowsupdate.com -> 146.75.118.172`, `fe2cr.update.microsoft.com -> 134.33.185.99, 132.196.74.208`, `ctldl.windowsupdate.com -> 146.75.122.172`                                                                                         |                                                                                                  |
| D-5 | **Suche 1: FEHLER 0x80072EFD, Suche 2: ERFOLG, Suche 3: ERFOLG** (5 s Abstand)                                                                                                                                                                                      | Hier wie auf der Pro-VM (Lauf 2, E-9): ab dem zweiten Versuch                                    |
| D-6 | Schlüsselwörter **nach** dem Versuch: `*.update.microsoft.com` = `20.165.94.63, 132.196.74.208, 134.33.185.99, 135.233.95.144`; `*.delivery.mp.microsoft.com` = `74.179.77.164`; `*.prod.do.dsp.mp.microsoft.com` = `72.145.35.111`; **`*.windowsupdate.com` leer** | `146.75.118.172` wurde trotz Auflösung **nicht gelernt** (anders als in Lauf 2, E-13)            |
| D-7 | 5157 im Zeitraum: `svchost.exe` → `146.75.118.172:80` (2×), `svchost.exe` → `172.211.123.248:443` (2×), `svchost.exe` → `20.165.94.63:443` (1×, danach gelernt)                                                                                                     | Zwei Ziele blieben unbekannt; die Suche gelang trotzdem, auf welchem Weg, ist **nicht gemessen** |

**Einordnung:** Auf dieser VM schlugen im ersten Block (Phase C, rund 1,5 Minuten nach dem Anlegen der Regeln) **alle neun Versuche** (3 Suchen, 3 BITS, 3 Signaturen) fehl, im Diagnoseblock elf Minuten später gelang die Suche ab dem zweiten Versuch. Warum, ist **nicht gemessen**. Eine Anlaufzeit nach dem Setzen des Netzwerkschutzes ist eine **Vermutung ohne Messung**. Die Aussage „mit der Option erreichbar“ ist damit auf **Pro 26H2 gemessen** und auf **Enterprise 25H2 nur in einem von zwei Messblöcken** bestätigt. Die Option ist nicht zuverlässig.

## Phase E und F: Rücknahme und Neustart

| Nr.  | Messwert (wörtlich)                                                                                                                                                                                                                     | Ergebnis          |
| ---- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------- |
| R-E1 | `Restore-EdepL1 -WhatIf` nennt Firewall-Import, Überwachungsrichtlinie, Telemetrie, DiagTrack, **zwei** App-Control-Richtlinien, „Update-Domain-Schlüsselwörter“ und „Zurück auf Disabled“ (Netzwerkschutz); „Es wurde nichts geändert“ | OK                |
| R-E2 | Restore: „Wiederherstellung abgeschlossen“, ohne Warnung                                                                                                                                                                                | OK                |
| R-E3 | Fingerabdruck nach Restore, vor dem Neustart: **identisch zu `vorher.json`** (Vergleich leer, Hash gleich). Netzwerkschutz `0`, Schlüsselwörter `0`, EDEP-Regeln `0`, `curl` `200`                                                      | OK                |
| R-E4 | `Test-EdepL1` nach Restore: **7/15** (NET-01, NET-02, NET-10, TEL-04, LOG-02, LOG-06 und **OPS-01** PASS)                                                                                                                               | OK (Abw. 5)       |
| R-F1 | Neustart 21:39:14 per `Restart-Computer -Force`. System-Protokoll: 1074 (User32, 21:39:34), 6006 (21:39:37), 6005 (21:39:51), Start 21:39:45; **kein** 41, **kein** 6008                                                                | sauberer Neustart |
| R-F2 | Nach dem Neustart: Fingerabdruck **identisch zu `vorher.json`**, Netzwerkschutz `0`, EDEP-Regeln `0`, `curl` `200`, `Test-EdepL1` 7/15                                                                                                  | OK                |

Der **Neustart-Vorfall (E-76) trat nicht auf**, bei **einem** Versuch (sofort nach dem Restore, 25 Sekunden Abstand).

## Abweichungen und Auslassungen

| Nr. | Was weicht ab oder fehlt                                                                                                                                                                                                   | Befund                                                                                   |
| --- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------- |
| 1   | **Update-Suche, BITS und `Update-MpSignature` scheiterten im ersten Messblock (neun von neun Versuchen)**, obwohl 9 Regeln und 9 Schlüsselwörter vorhanden waren und TEL-04 „Regeln und Netzwerkschutz vorhanden“ meldete. | Ursache nicht gemessen; im Diagnoseblock gelang die Suche ab Versuch 2.                  |
| 2   | `*.windowsupdate.com` lernte `146.75.118.172` im Diagnoseblock nicht (D-6).                                                                                                                                                | Widerspricht E-13 aus Lauf 2 (dort gelernt, mit Verzögerung). Unterschied nicht geklärt. |
| 3   | Diagnoseblock: Spalte „Adressen“ falsch (zählt leere Liste als 1).                                                                                                                                                         | Fehler im Messbefehl, nur die Spalte „Liste“ gilt.                                       |
| 4   | R-A7 und R-C6 (Edge) nicht beantwortet.                                                                                                                                                                                    | **nicht gemessen**. Nach Rückfrage keine Antwort.                                        |
| 5   | Nach Restore 7/15 statt 6/15.                                                                                                                                                                                              | EDEP-OPS-01 meldet PASS, weil die Sicherungen bewusst liegen bleiben. Kein Fehler.       |
| 6   | Die Ausgabe von Phase E erreichte mich nicht im Chat, sie liegt in `transcript-E.txt` und wurde dort geprüft.                                                                                                              |                                                                                          |
| 7   | B-01: BITS zu `example.org` unter Enforce blockiert (SPEC nennt „gelingt“).                                                                                                                                                | wie in den früheren Läufen, in SPEC B-01 geführt.                                        |
| 8   | Der Computername der VM (`DESKTOP-QKILAOK`) ist ein Standardname.                                                                                                                                                          |                                                                                          |

Nicht gemessen: Updateinstallation, fremder Virenschutz, DoH, Windows 11 Home, Windows Server, andere Sprachen, SYSTEM-initiierte Scans (E-87), DiagTrack im Audit-Modus (E-86), `cargo test` des L2-Agenten (E-65).

## Fazit Lauf 3

**Bestätigt (Enterprise 25H2, veröffentlichter Stand `0.1.0-draft.2`):**

- Audit-Modus 14/15, Enforce mit `-AllowWindowsUpdate` 15/15, Hashes des Tags stimmen.
- Unbekannte Programme und die LOLBin-Liste werden blockiert (5157 mit Pfad), B-05 wird von NET-04 erkannt, beschreibbare Pfade werden abgewiesen (NET-10).
- `Restore-EdepL1` stellt Firewall, Netzwerkschutz und Schlüsselwörter her, auch nach dem Neustart: Fingerabdruck identisch zum Zustand vor EDEP.

**Nicht bestätigt:**

- Die Erreichbarkeit der Updates unter Enforce mit der Option. Erster Block: 0 von 9 Versuchen, Diagnoseblock: Suche ab Versuch 2. **Die Option ist auf Enterprise nicht zuverlässig**; Defender-Signaturen gelingen nicht.
- Edge unter Enforce (nicht beantwortet).

**Einordnung:** Auch dieser Lauf ist **kein Konformitätsnachweis** (Entwurf). Er stützt die Aussage „erreichbar mit Verzögerung, nicht zuverlässig, nicht für Einzelaufrufe“ und ergänzt, dass auch das **ausbleiben kann**.
