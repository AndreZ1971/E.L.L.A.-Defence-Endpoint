# Testprotokoll L1-Durchlauf

Vorlage zu [docs/TESTPLAN-L1.md](../../docs/TESTPLAN-L1.md). Messwerte **wörtlich** eintragen.
Abweichungen nicht anpassen, sondern führen.

## Umgebung

|                                    |                                                           |
| ---------------------------------- | --------------------------------------------------------- |
| Datum, Uhrzeit                     |                                                           |
| Durchgeführt von                   |                                                           |
| Windows-Edition (`winver`)         |                                                           |
| Build (`[Environment]::OSVersion`) |                                                           |
| Defender-Plattformversion          |                                                           |
| Umgebung | Hyper-V-VM (Generation, vCPU / RAM / Platte) · Windows-Sandbox (Konfigurationsdatei) · andere: |
| Sprache                            |                                                           |
| Getesteter Commit                  |                                                           |
| Hash-Liste der Skripte             | `hashes.txt`                                              |
| Updates vor dem Test               | alle installiert, Neustart, Pausierung gesetzt: ja / nein |
| Checkpoint S0 angelegt             | ja / nein                                                 |

## Ergebnisse

Ergebnis: **OK** (Erwartung eingetreten), **ABW** (abweichend), **AUS** (ausgelassen, Grund angeben).

### Phase A: Ausgangszustand

| Nr.  | Messwert (wörtlich)     | Ergebnis |
| ---- | ----------------------- | -------- |
| R-A1 | Punktzahl:              |          |
| R-A2 | PASS/FAIL je Prüfung:   |          |
| R-A3 | `vorher.json` gesichert |          |
| R-A4 | Statuscode:             |          |
| R-A5 | Statuscode:             |          |
| R-A6 | Übertragung:            |          |
| R-A7 |                         |          |

### Phase B: Audit-Modus

| Nr.  | Messwert (wörtlich)      | Ergebnis |
| ---- | ------------------------ | -------- |
| R-B1 |                          |          |
| R-B2 | Fingerabdruck identisch: |          |
| R-B3 | Sicherungsordner:        |          |
| R-B4 | PASS/FAIL je Prüfung:    |          |
| R-B5 |                          |          |
| R-B6 | Statuscode:              |          |
| R-B7 |                          |          |

### Phase C: Erzwingen

| Nr.   | Messwert (wörtlich)                   | Ergebnis |
| ----- | ------------------------------------- | -------- |
| R-C1  |                                       |          |
| R-C2  | Zusammenfassungszeile:                |          |
| R-C3  |                                       |          |
| R-C4  |                                       |          |
| R-C5  |                                       |          |
| R-C6  |                                       |          |
| R-C7  | Windows Update: / Update-MpSignature: |          |
| R-C8  |                                       |          |
| R-C9  | Fehlermeldung:                        |          |
| R-C10 | nach Neustart:                        |          |
| R-C11 | Plattform vorher / nachher:           |          |

### Phase D: Umgehungen

| Nr.  | Messwert (wörtlich) | Ergebnis |
| ---- | ------------------- | -------- |
| R-D1 | Ereignis 3 / 59:    |          |
| R-D2 |                     |          |
| R-D3 |                     |          |
| R-D4 | Befehl und Ausgabe: |          |
| R-D5 |                     |          |
| R-D6 |                     |          |

### Phase E: Rücknahme

| Nr.  | Messwert (wörtlich)   | Ergebnis |
| ---- | --------------------- | -------- |
| R-E1 |                       |          |
| R-E2 |                       |          |
| R-E3 |                       |          |
| R-E4 |                       |          |
| R-E5 | Fingerabdruck gleich: |          |
| R-E6 |                       |          |

### Phase F: Wiederholbarkeit (nur Lauf 1)

| Nr.  | Messwert (wörtlich)                           | Ergebnis |
| ---- | --------------------------------------------- | -------- |
| R-F1 |                                               |          |
| R-F2 | Anzahl Regeln in `EDEP-L1` nach 1. / 2. Lauf: |          |

## Abweichungen und Auslassungen

| Nr. | Was weicht ab oder fehlt | Vermutete Ursache | Folge (Skript / Doku / Test) |
| --- | ------------------------ | ----------------- | ---------------------------- |
|     |                          |                   |                              |

## Fazit

|                                                |                  |
| ---------------------------------------------- | ---------------- |
| Alle Erwartungen eingetreten                   | ja / nein        |
| E-63 / E-64 für diese Edition und diesen Build | gemessen / offen |
| Erratum nötig                                  | ja (Nr.) / nein  |
