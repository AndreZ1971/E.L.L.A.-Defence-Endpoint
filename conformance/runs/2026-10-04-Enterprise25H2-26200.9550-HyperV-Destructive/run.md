# Testprotokoll: Stufe „Destructive“ von Test-EdepConformance.ps1 (Enterprise-VM)

**Stand: gemessen 2026-10-04, 19:59 bis 20:08 (Uhr der VM). Erste Läufe der neuen Stufe; zwei Läufe in der Enterprise-VM.** Hyper-V-VM `EDEP-Test-Ent`, Windows 11 Enterprise Evaluation 25H2, Build 26200.9550, Computername `DESKTOP-QKILAOK`, Stand mit `conformance/EdepConformance.Destructive.ps1` (noch nicht committet zum Zeitpunkt der Messung). Der Lauf wurde vom Host über PowerShell Direct gesteuert. Rohdaten in [beweise/](beweise/).

**Verfahren:** `Test-EdepConformance.ps1 -SkipIntegrity -Destructive -ConfirmDestructive` im Gast (Administrator, Ausgangszustand ohne EDEP, alle Profile `Allow`), danach ordentlicher Neustart des Gastes und Vergleich mit dem Ausgangszustand. Beschreibung der Stufe: [conformance/README.md](../../README.md).

**Erwartung vorab:** 13 Schritte, alle PASS; nach dem Neustart 7 von 15 und 0 Abweichungen zum Ausgangszustand.

## Lauf 1 (19:59 bis 20:02)

| Nr. | Messwert (wörtlich) | Einordnung |
|---|---|---|
| L1-1 | `Ausgangszustand: DESKTOP-QKILAOK, Admin True, EDEP-Regeln 0, Domain=Allow Private=Allow Public=Allow` | sauberer Ausgangszustand |
| L1-2 | `D-A1` bis `D-C4` (acht Schritte): `curl.exe 200, x.exe 200`; Audit: nur `EDEP-NET-03` nicht erfüllt, `curl.exe` `000`, umbenannte Kopie `200`; Enforce: alle 15 erfüllt, `curl.exe` `000`, Kopie `000`, BITS `FEHLER` | **alle PASS** |
| L1-3 | `D-D1  -AllowProgram mit beschreibbarem Pfad bricht ab (EDEP-NET-10)  [Abbruch: AllowProgram nicht …` | **FAIL, Fehler in der Stufe, keine Abweichung von EDEP:** Die Stufe hatte die Testdatei `edep-test.exe` nicht angelegt, `Install-EdepL1` meldete „nicht gefunden“, bevor es die Rechte prüfte |
| L1-4 | `D-D2`, `D-D3`, `D-D4`, `D-E1`: Bypass-Regel führt zu `EDEP-NET-04 = FAIL`, uneingeschränkte Regel zu `EDEP-NET-03 = FAIL`, `0 Reste`, Fingerabdruck `identisch` | alle PASS |
| L1-5 | `Protokoll: bestanden 12, fehlgeschlagen 1, nicht prüfbar 0, Rücknahme ausgeführt True, Fingerabdruck identisch True, Fehler 0`; `Exit-Code der Stufe: 1` | 12 von 13 |
| L1-6 | Nach ordentlichem Neustart: `7/15 erfüllt; Abweichungen zum Ausgangszustand: 0` | Ausgangszustand wiederhergestellt |

## Lauf 2 mit korrigierter Stufe (20:04 bis 20:08)

Korrektur: Die Stufe legt vor dem Schritt D-D1 eine Kopie von `curl.exe` im Benutzerprofil an; „Programm nicht gefunden“ gilt jetzt als `NOT_ASSESSABLE`, nicht als FAIL.

| Nr. | Messwert (wörtlich) | Einordnung |
|---|---|---|
| L2-1 | `Korrigierte Stufe in der VM: 1 (erwartet 1)` | Korrektur in der VM angekommen |
| L2-2 | `D-A1` bis `D-E1`: **13 von 13 PASS**, darunter `D-D1: PASS \| Abbruch: AllowProgram 'C:\Users\test\AppData\Local\edep-test.exe' ist für Nicht-Administratoren änderbar und darf nicht freigegeben werden (EDEP-NET-10):` | **alle Erwartungen eingetreten** |
| L2-3 | `Protokoll: bestanden 13, fehlgeschlagen 0, nicht prüfbar 0, Rücknahme ausgeführt True, Fingerabdruck identisch True, Fehler 0`; `Exit-Code der Stufe: 1` | Der Exit-Code 1 kommt vom ungehärteten Ausgangszustand (7 von 15 vor der Stufe), nicht von der Stufe |
| L2-4 | Protokoll (Rohdatei): `destructive.passed` 13, `failed` 0, `restored` true, `fingerprintIdentical` true; `notRun` 7 Tests (`T-NET-02a`, `T-TEL-02a`, `T-TEL-04a`, `T-OPS-05`, `T-INF-04`, `T-BYP-02`, `T-BYP-03`) | Die in der Stufe ausgeführten Tests sind aus `notRun` verschwunden (vorher 19) |
| L2-5 | Nach ordentlichem Neustart: `7/15 erfüllt; Abweichungen zum Ausgangszustand: 0` | Ausgangszustand wiederhergestellt |

## Abweichungen

| Nr. | Was weicht ab | Befund |
|---|---|---|
| 1 | D-D1 in Lauf 1 | Fehler der Stufe, in Lauf 2 behoben (siehe oben) |
| 2 | Die Rohdatei von Lauf 2 lag auf dem Host zunächst unter dem Namen `lauf2` statt in einem Ordner | Fehler im Kopierblock (`Copy-Item` mit nicht vorhandenem Zielordner); die Datei ist inhaltlich unverändert und in `beweise/` unter ihrem Zeitstempelnamen abgelegt |
| 3 | Nicht gemessen | Stufe auf Windows 11 Pro; Integrität PASS in diesem Lauf (`-SkipIntegrity`); `-AllowProgram` mit Edge war gesetzt (Edge vorhanden), das Laden der Seite wird von der Stufe nicht geprüft |

## Fazit

Die Stufe „Destructive“ läuft in der Enterprise-VM durch: **13 von 13 Schritten** erfüllen die Erwartung (nach Korrektur eines Fehlers der Stufe), die Rücknahme stellt den Ausgangszustand her (Fingerabdruck identisch, auch nach einem ordentlichen Neustart). Das bestätigt die Zusagen aus Lauf 3 und 4 (Audit 14/15, Enforce 15/15, Umgehungen B-01, B-04, B-05, B-07, B-08) in **einem** Aufruf. Kein Konformitätsnachweis: Die Tests unter `notRun` laufen nicht.
