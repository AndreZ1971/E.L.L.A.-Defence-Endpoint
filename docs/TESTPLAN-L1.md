# Testplan L1: vollständiger VM-Durchlauf

**Ziel:** Die Nachweise [E-63 und E-64](EVIDENCE.md) schließen. Das heißt: L1 wird auf einem frischen Windows
angewendet, erzwungen, in seiner Wirkung gemessen, an den bekannten Umgehungen geprüft und wieder
vollständig zurückgenommen. Jede Erwartung stammt aus [SPEC.md](../SPEC.md) und dem
[Konformitätskatalog](../conformance/README.md). Das Protokoll kommt nach `conformance/runs/`.

**Grundsatz:** Ein Test, der nur „bestanden“ kennt, beweist nichts. Deshalb gibt es zu jeder Wirkungsprüfung
eine **Kontrollmessung vorher** (ohne EDEP muss es gelingen) und eine **Messung nachher**. Nur der Unterschied
ist der Beleg. Bekannte Umgehungen werden als „gelingt“ erwartet und müssen **genau so** ausgehen.

---

## 1. Was dieser Test beweist und was nicht

| Beweist                                                           | Beweist nicht                                                             |
| ----------------------------------------------------------------- | ------------------------------------------------------------------------- |
| L1 lässt sich anwenden, erzwingen, prüfen und zurücknehmen        | Verhalten auf Hardware mit anderer Netzwerkausstattung (WLAN, VPN, Proxy) |
| Die Wirkung tritt ein: Unbekanntes bleibt draußen, Erlaubtes geht | Windows Home, andere Sprachen als Deutsch                                 |
| Die dokumentierten Umgehungen verhalten sich wie beschrieben      | Langzeitverhalten über mehrere Feature-Updates                            |
| Einstellungen überstehen einen Neustart                           | Alles, was L2 und L3 betrifft                                             |

---

## 2. Vor dem Start: Entscheidungen

| #   | Frage                     | Empfehlung                                                                                                                                                                                                | Entscheidung                                                                                                                                |
| --- | ------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | Wo wird getestet?         | **Hyper-V-VM auf Laufwerk E:** (194 GB frei, Hypervisor läuft bereits). Nicht auf dem Arbeitsrechner.                                                                                                     | **entschieden** (Lauf 1; Evaluierungs-ISO wird geladen, Stand 2026-10-03)                                                                   |
| 2   | Welche Editionen?         | Lauf 1: **Windows 11 Enterprise (Evaluierung)**, weil dort „Diagnostic data off“ existiert. Lauf 2: **Windows 11 Pro**, weil das die häufigste Zielgruppe ist.                                            | **entschieden**                                                                                                                             |
| 3   | Windows-Sandbox statt VM? | **Ja, als Lauf 1 möglich** (siehe Anhang B): braucht kein Image und keinen Account, startet bei jedem Mal frisch. Gilt als „Windows-Sandbox“, nicht als vollständige VM. Der Update-Test bleibt fraglich. | **erledigt als Lauf 0** (2026-10-02, nur Entdeckungslauf; App Control, Defender, Windows Update dort nicht prüfbar, daher Lauf 1 in der VM) |
| 4   | Wer führt aus?            | Du mit Adminrechten, ich begleite und werte aus.                                                                                                                                                          | **entschieden** (in Lauf 0 bewährt)                                                                                                         |

---

## 2a. Vorab geprüft (2026-10-01, ohne Änderung am System)

| Was                                                                                                                                  | Ergebnis                                                                                                                                              |
| ------------------------------------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------- |
| Arbeitsrechner                                                                                                                       | Windows 11 Pro for Workstations, Build **10.0.26300** (gestern 26200: Update KB5121794 ist beim Neustart heute 14:26 wirksam geworden)                |
| Platz für die VM                                                                                                                     | **E: 194 GB frei**; C: nur 12 GB, daher ungeeignet                                                                                                    |
| Hypervisor                                                                                                                           | läuft bereits (VBS aktiv), Hyper-V-Modul vorhanden                                                                                                    |
| NET-10 für die vom Installer selbst freigegebenen Programme (Defender `MsMpEng.exe`, `MpCmdRun.exe`, `smartscreen.exe`) und für Edge | bestanden: nur Admin/SYSTEM/TrustedInstaller dürfen ändern. Die Erwartung „15 von 15“ in R-C2 scheitert also nicht an der Installer-eigenen Freigabe. |
| Offene Hypothese                                                                                                                     | `UsoSvc` fehlt in der Dienstliste (siehe R-C7)                                                                                                        |

Alles in Abschnitt 4 ist bis zum Lauf eine **Erwartung**, kein Ergebnis.

---

## 3. Vorbereitung (einmalig, ca. 60 min)

| Schritt | Aktion                                                                                                                                                                                                     | Nachweis                                                           |
| ------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------ |
| V1      | VM anlegen: Generation 2, 4 vCPU, 6 GB RAM, 80 GB Platte **auf E:**, Secure Boot und TPM an, Netzwerk „Default Switch“                                                                                     | Einstellungen notieren                                             |
| V2      | Windows installieren (Sprache Deutsch)                                                                                                                                                                     | Edition aus `winver`                                               |
| V3      | **Alle Updates installieren, neu starten, erneut suchen, bis keines mehr kommt.** Ein Update mitten im Test würde das Ergebnis verfälschen (Build ändert sich, Defender-Plattformpfad wechselt, Neustart). | Build aus `[Environment]::OSVersion`, Stand der Defender-Plattform |
| V4      | Ein Update während der Tests ausschließen: Einstellungen → Windows Update → Aktualisierungen für 1 Woche pausieren. In Schritt C7 wird das Pausieren für die Update-Prüfung kurz aufgehoben.               | Screenshot                                                         |
| V5      | Repo **in einer festen Version** holen: ZIP von GitHub, den **Commit-Hash** aus der Adresse oder `git rev-parse HEAD` notieren. Die Skripte vor dem Start mit `Get-FileHash` ins Protokoll aufnehmen.      | Commit-Hash, Hash-Liste                                            |
| V6      | Aufzeichnung starten: `New-Item -ItemType Directory C:\edep-run -Force; Start-Transcript -Path C:\edep-run\transcript.txt`                                                                                 | Datei                                                              |
| V7      | **Checkpoint „S0-sauber“** anlegen                                                                                                                                                                         | Name und Zeit                                                      |

**Erst wenn V1 bis V7 erledigt sind, geht es weiter.** Jeder Schritt danach darf mit einem Zurücksetzen auf S0 wiederholt werden.

---

## 4. Ablauf

Jeder Schritt hat eine Nummer (`R-…`), die im Protokoll wieder auftaucht. Spalte **T-ID** verweist auf den
Konformitätstest, den der Schritt abdeckt. Befehle: PowerShell **als Administrator**, im Ordner `baseline\L1`,
sofern nicht anders angegeben.

### Hinweise aus Lauf 1 (Hyper-V, 2026-10-03), vor Phase A lesen

| Thema | Hinweis |
|---|---|
| Ausführungsrichtlinie | Auf einem frischen Windows startet kein Skript. Pro PowerShell-Sitzung: `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` (Abweichung 2). |
| Rückfragen | Auf **deutschem** Windows `J` (oder `A` für alle), nicht `y`. Mit `-DeployAppControlAudit` sechs Rückfragen beim Installer, beim Restore vier plus eine je App-Control-Richtlinie (Abweichungen 3, 4). Für den Lauf ohne Pause: `-Confirm:$false`. |
| Ausgaben in Dateien | `Test-EdepL1.ps1` schreibt mit `Write-Host`; `Tee-Object` und `Out-File` erfassen nichts. Für Dateien `-Json` verwenden (Abweichung 12). |
| Updates pausieren | Die Oberfläche genügt nicht als Beleg. Nach dem Pausieren `Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings'` prüfen (Abweichung 1). Defender-Plattform vor und nach dem Lauf notieren. |
| Update-Messungen (R-C7) | Vor **jeder** Messung den Cache zurücksetzen (`SoftwareDistribution` umbenennen), sonst gelingt die Suche aus dem Cache (Abweichung 16). Messung über `Microsoft.Update.Session`, Blockaden über Ereignis 5157 mit Zuordnung `PID` zu Dienst (`Get-CimInstance Win32_Service -Filter "ProcessId=<PID>"`). |
| Neustart | Vor einem Neustart `Stop-Transcript`. Nach einer Rücknahme mit anschließendem Neustart `Test-EdepL1.ps1` ausführen (7/15 erwartet; Abweichung 11 trat einmal auf). |
| Dateien aus der VM holen | Auf dem Host in einer Administrator-PowerShell: `New-PSSession -VMName <Name> -Credential (Get-Credential)` und `Copy-Item -FromSession`. Läuft über Hyper-V und funktioniert auch unter „ausgehend Block“. |
| Checkpoint | Im VM-Fenster „Aktion → Prüfpunkt“ genügt; der Name entsteht automatisch und lässt sich im Hyper-V-Manager umbenennen. |
| Erwartung R-C7 | **Ohne** `-AllowWindowsUpdate` scheitert die Update-Suche unter Enforce (Abweichungen 6, 7). **Mit** der Option gelingt sie nach höchstens drei Versuchen, BITS zu Microsoft nach höchstens zwei, `example.org` bleibt gesperrt (E-88). Der Netzwerkschutz steht danach im Audit-Modus und wird beim Restore zurückgestellt (E-90). |

### Phase A: Ausgangszustand messen (auf S0)

Ziel: wissen, wie die VM ohne EDEP aussieht. Ohne diese Werte ist später kein Vorher-Nachher-Vergleich möglich.

| Nr.  | Aktion                                                                                             | Erwartung                                                                                                                                                                                                 | T-ID      |
| ---- | -------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------- |
| R-A1 | `.\Invoke-EdepAudit.ps1 -NoHtml -PassThru`, Punktzahl und Befunde sichern                          | läuft ohne Fehler, ändert nichts                                                                                                                                                                          |           |
| R-A2 | `.\Test-EdepL1.ps1 -Json`, Ausgabe sichern                                                         | NET-03, NET-04, NET-05, TEL-01, TEL-02, TEL-03, LOG-01, OPS-01 = FAIL; NET-10 = PASS; ID-01 = FAIL (VM: keine Richtlinie, Sandbox: CiTool nicht verfügbar); NET-01, NET-02, TEL-04, LOG-02, LOG-06 = PASS |           |
| R-A3 | **Fingerabdruck** sichern (siehe Abschnitt 6)                                                      | Datei `vorher.json`                                                                                                                                                                                       | T-OPS-01a |
| R-A4 | Kontrolle Netz: `curl.exe -m 10 -s -o NUL -w "%{http_code}" https://example.org`                   | `200`                                                                                                                                                                                                     |           |
| R-A5 | Kontrolle unbekanntes Programm: Kopie von `curl.exe` als `$env:TEMP\x.exe`, gleicher Aufruf        | `200`                                                                                                                                                                                                     |           |
| R-A6 | Kontrolle BITS: `Start-BitsTransfer -Source https://example.org -Destination $env:TEMP\bits0.html` | gelingt                                                                                                                                                                                                   | T-BYP-01  |
| R-A7 | Kontrolle Edge: öffnet eine Seite                                                                  | lädt                                                                                                                                                                                                      |           |

**Abbruch, wenn R-A4 bis R-A7 nicht gelingen:** Dann ist das Netz der VM defekt, und spätere „blockiert“-Ergebnisse
wären wertlos.

### Phase B: Trockenlauf und Audit-Modus

| Nr.  | Aktion                                                                                                                                                 | Erwartung                                                                                                                                                                                                               | T-ID      |
| ---- | ------------------------------------------------------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------- |
| R-B1 | `.\Install-EdepL1.ps1 -DeployAppControlAudit -WhatIf`                                                                                                  | „Es wurde nichts geändert“                                                                                                                                                                                              | T-OPS-02  |
| R-B2 | Fingerabdruck erneut sichern                                                                                                                           | **identisch** zu `vorher.json` (WhatIf ändert nichts)                                                                                                                                                                   |           |
| R-B3 | `.\Install-EdepL1.ps1 -DeployAppControlAudit` (ohne `-Enforce`) (in der Sandbox ohne `-DeployAppControlAudit`: CiTool dort nicht verfügbar)            | endet ohne Fehler; Sicherung unter `C:\ProgramData\EDEP\backup\<Zeit>` mit `manifest.json`, `firewall.wfw`, `auditpol.csv`; 5 Rückfragen (je Schritt `y`)                                                               | T-OPS-01  |
| R-B4 | `.\Test-EdepL1.ps1`                                                                                                                                    | NET-03 = FAIL (Audit-Modus, ausgehend noch erlaubt); NET-04, NET-05, NET-10, TEL-01 (Enterprise; Pro: WARN), TEL-02, TEL-03, LOG-01, OPS-01 = PASS; ID-01 = PASS in einer VM mit App-Control-Audit, in der Sandbox FAIL | T-OPS-02  |
| R-B5 | `curl.exe -m 10 -s -o NUL -w "%{http_code}" https://example.org`                                                                                       | **blockiert** (LOLBin-Regel greift schon im Audit-Modus)                                                                                                                                                                | T-NET-04a |
| R-B6 | Aufruf von `$env:TEMP\x.exe` wie in R-A5                                                                                                               | **gelingt** (`200`): Umgehung **B-07** im Audit-Modus, genau wie beschrieben                                                                                                                                            | T-BYP-07  |
| R-B7 | `Get-WinEvent -FilterHashtable @{LogName='Security';Id=5157} -MaxEvents 5` (erst ca. 30 s nach dem Versuch; die Ereignisse erscheinen verzögert, E-70) | Einträge zu `curl.exe`                                                                                                                                                                                                  | T-LOG-01  |

### Phase C: Erzwingen und Wirkung messen

| Nr.   | Aktion                                                                                                                                | Erwartung                                                                                                                                                                                                                                                                                               | T-ID         |
| ----- | ------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------ |
| R-C1  | `.\Install-EdepL1.ps1 -Enforce -DeployAppControlAudit -AllowWindowsUpdate -AllowProgram "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe"` | endet ohne Fehler                                                                                                                                                                                                                                                                                       |              |
| R-C2  | `.\Test-EdepL1.ps1`                                                                                                                   | 15/15 erfüllt **mit** `-AllowWindowsUpdate` (TEL-04 dabei als **WARN**, Wirkung ungemessen; mit `-ProbeUpdates` gemessen); **ohne** die Option 14/15 (TEL-04 FAIL, Updates nicht erreichbar, DD-13) (Sandbox: 14/15, nur ID-01; die Image-Regel `Container: allow outbound` muss vorher ausgeschaltet sein, sonst FAIL bei NET-03)                                                                                                                                                            | alle L1-auto |
| R-C3  | Aufruf von `$env:TEMP\x.exe` wie in R-A5                                                                                              | **blockiert** (Sandbox: nur nach Ausschalten **aller** Regeln `Container: allow outbound`, siehe Abweichung 8)                                                                                                                                                                                          | T-NET-03a    |
| R-C4  | `curl.exe` wie in R-A4                                                                                                                | **blockiert**                                                                                                                                                                                                                                                                                           | T-NET-04a    |
| R-C5  | Ereignis 5157 für `x.exe` und `curl.exe` vorhanden                                                                                    | ja, mit Programmpfad                                                                                                                                                                                                                                                                                    | T-LOG-01     |
| R-C6  | Edge öffnet eine Seite                                                                                                                | **lädt**                                                                                                                                                                                                                                                                                                |              |
| R-C7  | Windows Update: Pausieren aufheben, „Nach Updates suchen“; danach `Update-MpSignature`                                                | beides erfolgreich, **keine Netzfehler**. _Hypothese:_ Der Update-Orchestrator `UsoSvc` steht nicht in der Liste der erlaubten Dienste. Scheitert die Suche, ist das ein **Befund**: `EdepRequiredServices` ergänzen, Erratum führen. (Sandbox: nicht herstellbar, Windows Update ist dort deaktiviert) | T-TEL-04a    |
| R-C8  | Regeln zu `DiagTrack` und `dmwappushservice` vorhanden (Befehl siehe [VERIFY-YOURSELF 2.2](VERIFY-YOURSELF.md))                       | beide Dienste aufgeführt                                                                                                                                                                                                                                                                                | T-TEL-02     |
| R-C9  | `.\Install-EdepL1.ps1 -AllowProgram "$env:LOCALAPPDATA\<beliebige .exe>" -WhatIf` (Datei dafür anlegen)                               | **Abbruch mit EDEP-NET-10**                                                                                                                                                                                                                                                                             | T-NET-10a    |
| R-C10 | **Neustart**, danach R-C2, R-C3, R-C4 wiederholen                                                                                     | gleiches Ergebnis wie vorher                                                                                                                                                                                                                                                                            |              |
| R-C11 | Defender-Plattformpfad vergleichen (Abschnitt 6)                                                                                      | gleich, oder bei Änderung: TEL-04 meldet „veraltet“ und `Install-EdepL1` behebt es                                                                                                                                                                                                                      | T-TEL-04     |

### Phase D: Umgehungen auslösen

Ergebnis muss **genau** der Beschreibung in [SPEC 3.4](../SPEC.md#34-bekannte-umgehungen-normativ) entsprechen.
Weicht es ab, ist entweder die Doku oder das Skript falsch; beides wird als Fehler verzeichnet.

| Nr.  | Umgehung                                | Aktion                                                                                | Erwartung                                                                                                                                               | T-ID     |
| ---- | --------------------------------------- | ------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------- | -------- |
| R-D1 | B-01 BITS                               | wie R-A6                                                                              | **Gemessen in Lauf 0 und Lauf 1: blockiert** (Abweichung 11 bzw. 8; SPEC B-01 entsprechend korrigiert). Ein anderes Ergebnis ist ein neuer Messwert; Ereignisse 3 und 59 prüfen | T-BYP-01 |
| R-D2 | B-03 erlaubtes Programm                 | Edge mit Adresse auf der Kommandozeile starten                                        | **gelingt** (Grenze jeder programmbasierten Firewall)                                                                                                   | T-BYP-03 |
| R-D3 | B-04 Benutzerpfad                       | siehe R-C9                                                                            | Abbruch                                                                                                                                                 | T-BYP-04 |
| R-D4 | B-05 Authenticated Bypass               | ausgehende Erlaubnisregel mit `-OverrideBlockRules` anlegen, danach `Test-EdepL1.ps1` | NET-04 meldet **FAIL**                                                                                                                                  | T-BYP-05 |
| R-D5 | B-07 umbenannte LOLBin im Enforce-Modus | wie R-A5                                                                              | **blockiert**                                                                                                                                           | T-BYP-07 |
| R-D6 | B-02 DNS-Tunnel                         | nur mit eigener Testdomain; sonst ausgelassen und so vermerkt                         | Anfrage erreicht den Server der Testdomain                                                                                                              | T-BYP-02 |

> **Hinweis zu R-D4:** Eine Regel mit „Blockregeln außer Kraft setzen“ verlangt laut Windows-Firewall-Dokumentation
> zusätzlich eine Authentifizierung (IPsec). Der genaue Befehl ist vor dem Lauf auf einer Wegwerf-VM zu klären.
> Scheitert das Anlegen, ist die **Fehlermeldung das Ergebnis**, und der Test wird als „nicht herstellbar“ vermerkt,
> nicht als bestanden.

### Phase E: Zurücknehmen

| Nr.  | Aktion                                               | Erwartung                                                                                                                                    | T-ID      |
| ---- | ---------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------- | --------- |
| R-E1 | R-D4-Regel entfernen, falls angelegt                 | Regel weg                                                                                                                                    |           |
| R-E2 | `.\Restore-EdepL1.ps1 -WhatIf`                       | zeigt die geplanten Schritte, ändert nichts                                                                                                  | T-OPS-01a |
| R-E3 | `.\Restore-EdepL1.ps1`                               | endet ohne Fehler                                                                                                                            | T-OPS-01a |
| R-E4 | Neustart, dann `.\Test-EdepL1.ps1`                   | 7/15, nicht 5/15 wie in R-A2: NET-10 ist nach der Korrektur PASS, OPS-01 bleibt PASS, weil die Sicherungen bestehen bleiben                  | T-OPS-01a |
| R-E5 | Fingerabdruck sichern, mit `vorher.json` vergleichen | **gleich** in allen Werten aus Abschnitt 6 (Sandbox: Regelanzahlen können abweichen, weil das Image beim Start Regeln anlegt, Abweichung 12) | T-OPS-01a |
| R-E6 | R-A4, R-A5, R-A6 wiederholen                         | gelingen wieder wie in Phase A                                                                                                               |           |

### Phase F: Wiederholbarkeit (nur bei Lauf 1)

| Nr.  | Aktion                                                                       | Erwartung                                                                               |
| ---- | ---------------------------------------------------------------------------- | --------------------------------------------------------------------------------------- |
| R-F1 | Auf **S0** zurücksetzen, Phase B bis C ohne Unterbrechung nochmals ausführen | gleiche Ergebnisse wie beim ersten Mal                                                  |
| R-F2 | `Install-EdepL1.ps1` **zweimal hintereinander** ausführen                    | zweiter Lauf endet ohne Fehler, keine doppelten Regeln in Gruppe `EDEP-L1` (Idempotenz) |

---

## 5. Protokollierung

Pro Lauf ein Ordner `conformance/runs/<Datum>-<Edition>-<Build>/` mit:

| Datei                                                                       | Inhalt                                                                                                             |
| --------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------ |
| `run.md`                                                                    | ausgefüllte [Vorlage](../conformance/runs/TEMPLATE.md): Umgebung, jeder Schritt, Erwartung, **Messwert**, Ergebnis |
| `transcript.txt`                                                            | Aufzeichnung der Sitzung                                                                                           |
| `vorher.json`, `nachher.json`                                               | Fingerabdrücke                                                                                                     |
| `audit-vorher.json`, `l1-vorher.json`, `l1-enforce.json`, `l1-nachher.json` | Prüfausgaben                                                                                                       |
| `hashes.txt`                                                                | SHA-256 aller getesteten Skripte und der Commit-Hash                                                               |

**Regeln:**

1. Messwerte werden **wörtlich** eingetragen (Ausgabe, Statuscode), nicht als „ok“.
2. Weicht ein Ergebnis von der Erwartung ab, wird es **nicht angepasst**, sondern als Abweichung geführt.
3. Auslassungen stehen mit Grund im Protokoll.
4. Bevor etwas veröffentlicht wird, werden Rechnername, Benutzername und Lizenzschlüssel aus den Dateien entfernt.

---

## 6. Fingerabdruck (Vorher-Nachher-Vergleich)

Ein reiner Hash der Firewall-Exportdatei taugt nicht, weil sich Regel-IDs und Reihenfolge ändern können.
Verglichen werden deshalb diese **inhaltlichen** Werte:

| Wert                                                                                | Quelle                                            |
| ----------------------------------------------------------------------------------- | ------------------------------------------------- |
| Standardaktionen je Profil (ein-/ausgehend), `LogBlocked`, `Enabled`                | `Get-NetFirewallProfile -PolicyStore ActiveStore` |
| Anzahl aktiver Regeln je Richtung und Aktion; Anzahl der Regeln in Gruppe `EDEP-L1` | `Get-NetFirewallRule`                             |
| Registrierungswerte aus `EdepRegistrySettings` (vorhanden ja/nein, Wert)            | `EdepL1.Common.ps1`                               |
| Überwachung „Filterplattformverbindung“ (Wert 0 bis 3)                              | `auditpol /backup`                                |
| Starttyp von `DiagTrack`                                                            | `Get-Service`                                     |
| aktive nicht-systemeigene App-Control-Richtlinien                                   | `CiTool -lp -json`                                |
| Defender-Plattformversion                                                           | `Get-MpComputerStatus`                            |

---

## 7. Auswertung

| Ergebnis                                   | Bedeutung                                                            | Folge                                                            |
| ------------------------------------------ | -------------------------------------------------------------------- | ---------------------------------------------------------------- |
| Alle Erwartungen eingetreten               | E-63/E-64 gelten für diese Edition und diesen Build als **gemessen** | Register aktualisieren, Protokoll veröffentlichen                |
| Erwartung nicht eingetreten, Skript falsch | echter Fehler                                                        | beheben, als Erratum verzeichnen, Lauf wiederholen               |
| Erwartung nicht eingetreten, Doku falsch   | Dokumentationsfehler                                                 | Doku und Erwartung korrigieren, als Erratum verzeichnen          |
| Schritt nicht herstellbar                  | Lücke im Test                                                        | als solche benennen, Register-Eintrag bleibt ⏳ für diesen Punkt |

E-63/E-64 werden **pro Edition und Build** abgehakt, nicht pauschal.

---

## 8. Risiken und Rettung

| Risiko                                          | Vorsorge                                                                                                                                |
| ----------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| VM verliert nach `-Enforce` das Netz            | Gewollt (Wirkung). Konsolenzugriff über Hyper-V; `Restore-EdepL1.ps1` arbeitet **offline**. Zur Not auf Checkpoint **S0** zurücksetzen. |
| Skript bricht mittendrin ab                     | Zurück auf S0 und von Phase A an wiederholen. Teilergebnisse nicht weiterverwenden.                                                     |
| Windows-Update startet mitten im Lauf           | V3 und V4 verhindern es. Kommt doch eines, wird der Lauf verworfen und neu gemacht.                                                     |
| Falsche Ergebnisse durch kaputtes Netz          | Kontrollmessungen R-A4 bis R-A7 und R-E6.                                                                                               |
| Versehentlich auf dem Arbeitsrechner ausgeführt | Install-Skripte zeigen den Rechnernamen; vor jedem Lauf `hostname` prüfen. Nichts davon gehört auf den Host.                            |

---

## 9. Aufwand

| Teil                                                    | Dauer                   |
| ------------------------------------------------------- | ----------------------- |
| Vorbereitung (V1 bis V7), davon Updates der größte Teil | ca. 60 bis 90 min       |
| Phasen A bis E                                          | ca. 90 min              |
| Phase F und Protokoll ausfüllen                         | ca. 45 min              |
| **Gesamt Lauf 1**                                       | **ca. 3 bis 4 Stunden** |
| Lauf 2 (zweite Edition, ohne Phase F)                   | ca. 2 Stunden           |

---

## Anhang A: VM anlegen (V1, V7)

**Quelle des Images:** [Windows 11 Enterprise, Microsoft Evaluation Center](https://www.microsoft.com/en-us/evalcenter/evaluate-windows-11-enterprise).
Laut Microsoft 90 Tage lauffähig und ohne Produktschlüssel, ausschließlich für Testumgebungen. Das Image ist nicht
auf dem Rechner vorhanden und muss zuerst geladen werden (ca. mehrere GB). Der Build des Images kann älter sein als der
des Arbeitsrechners; V3 holt ihn auf den aktuellen Stand, und das Protokoll hält ihn fest.

**Ausführen als Administrator** (nicht als normaler Benutzer; die Sitzung braucht Hyper-V-Rechte). Pfade und den Namen
der ISO-Datei vorher anpassen:

```powershell
$name = 'EDEP-Test-Ent'
$base = 'E:\VMs\' + $name
New-Item -ItemType Directory -Path $base, 'E:\ISO' -Force | Out-Null

New-VM -Name $name -Generation 2 -MemoryStartupBytes 6GB -SwitchName 'Default Switch' `
       -NewVHDPath "$base\disk.vhdx" -NewVHDSizeBytes 80GB -Path $base
Set-VM -Name $name -ProcessorCount 4 -AutomaticCheckpointsEnabled $false
Set-VMFirmware -VMName $name -EnableSecureBoot On
Set-VMKeyProtector -VMName $name -NewLocalKeyProtector
Enable-VMTPM -VMName $name

Add-VMDvdDrive -VMName $name -Path 'E:\ISO\<windows-11-enterprise-eval>.iso'
Set-VMFirmware -VMName $name -FirstBootDevice (Get-VMDvdDrive -VMName $name)

Start-VM -Name $name
vmconnect.exe localhost $name
```

Nach V3 bis V6 (Windows installiert, aktualisiert, pausiert, Repo geholt):

```powershell
Checkpoint-VM -Name 'EDEP-Test-Ent' -SnapshotName 'S0-sauber'
```

Zurücksetzen (nach einem Fehlversuch oder für Phase F):

```powershell
Restore-VMCheckpoint -VMName 'EDEP-Test-Ent' -Name 'S0-sauber' -Confirm:$false
```

**Hinweise:** Die automatischen Checkpoints sind absichtlich aus, damit nur S0 existiert. Beim Installieren der
VM kann die Meldung „Press any key to boot from CD“ erscheinen; dann sofort eine Taste drücken.
Das Image bleibt bis zu 90 Tage nutzbar; danach neu aufsetzen.

---

## Anhang B: Windows-Sandbox statt VM

Für Rechner mit Windows Pro, Enterprise oder Education. Nach
[Microsoft](https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/)
ist die Sandbox eine Wegwerf-VM: Beim Schließen wird **alles** gelöscht, jeder Start ist wie frisch installiert, Neustarts
aus der Sandbox heraus überstehen die Daten (ab Windows 11 22H2), das Netz ist standardmäßig an, und es läuft nur eine
Instanz gleichzeitig. Software des Hosts ist darin nicht vorhanden.

**Was dadurch einfacher wird:** Kein Image, kein Account, kein Platz auf einem Stick. Checkpoint **S0** ist jeder frische
Start, Phase F besteht aus „Sandbox schließen, neu starten“. Updates des Hosts (V3, V4) sind für die Sandbox selbst nicht nötig; sie holt sich ihr Image beim Start.

**Was anders ist (im Protokoll angeben):**

| Punkt                            | Folge                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| -------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Edition und Build der Sandbox    | **Gemessen am 2026-10-02** (Lauf mit Host Windows 11 Pro for Workstations 26H2, Build 26300.9550): Die Sandbox war **Windows 11 Enterprise 24H2, Build 10.0.26100, UBR 9550**, Benutzer `WDAGUtilityAccount` mit Adminrechten. Edition und Build der Sandbox sind also **nicht** die des Hosts. Sie werden in S2 gemessen und im Protokoll festgehalten. Eintrag z. B. „Windows 11 Enterprise 24H2, Build 26100.9550, **Windows-Sandbox**“. Das ist **nicht** „Pro“ und **keine** vollständig installierte Enterprise-Version. |
| Keine vollständige Installation  | Ergebnis gilt für die Sandbox, nicht für ein installiertes System. Das Register führt es als eigene Umgebung.                                                                                                                                                                                                                                                                                                                                                                                                                  |
| Windows Update (R-C7, T-TEL-04a) | **ungeprüft**, ob die Sandbox das kann. Erst versuchen: Gelingt es, Messwert eintragen. Gelingt es nicht, wird der Schritt als **„nicht herstellbar“** geführt, nicht als bestanden.                                                                                                                                                                                                                                                                                                                                           |
| Alles in einer Sitzung           | Wird das Fenster geschlossen, ist alles weg. Zwischenstände vorher sichern (siehe unten).                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| `UsoSvc`-Hypothese               | gilt unverändert (R-C7)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |

> **Korrigierte Annahme (2026-10-02):** Zuerst stand hier, die Sandbox übernehme Edition und Build des Hosts. Das war falsch. Sie hat ein eigenes Image (Enterprise 24H2) und lädt beim ersten Start **eigene Updates** (Fenster „Updates werden heruntergeladen und installiert“). Der getestete Build steht deshalb erst nach S2 fest.

### Einmalig vorbereiten (Administrator, danach Neustart)

```powershell
Enable-WindowsOptionalFeature -Online -FeatureName Containers-DisposableClientVM -All
New-Item -ItemType Directory -Path E:\edep-results -Force | Out-Null
```

Die Konfigurationsdatei `E:\EDEP-Sandbox.wsb` (Texteditor, Endung `.wsb`). Sie bindet **nur** einen leeren
Ergebnisordner schreibbar ein. Das Repo wird absichtlich **nicht** eingebunden (siehe V5 unten):

```xml
<Configuration>
  <VGpu>Disable</VGpu>
  <Networking>Default</Networking>
  <MemoryInMB>8192</MemoryInMB>
  <MappedFolders>
    <MappedFolder>
      <HostFolder>E:\edep-results</HostFolder>
      <SandboxFolder>C:\edep-out</SandboxFolder>
      <ReadOnly>false</ReadOnly>
    </MappedFolder>
  </MappedFolders>
</Configuration>
```

Start: Doppelklick auf `E:\EDEP-Sandbox.wsb`. Die Sandbox öffnet sich als Fenster. Darin eine **PowerShell als
Administrator** öffnen (der Sandbox-Benutzer ist Administrator).

### Vorbereitung in der Sandbox (ersetzt V1 bis V7)

| Schritt | Aktion                                                                                                                                                                                                                                                                                                     | Nachweis                                  |
| ------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------- |
| S1      | `New-Item -ItemType Directory C:\edep-run -Force; Start-Transcript -Path C:\edep-run\transcript.txt`                                                                                                                                                                                                       | Datei                                     |
| S2      | `whoami`, `[Environment]::OSVersion`, `EditionID`, `DisplayVersion` und **`UBR`** aus `HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion`, Adminprüfung (muss `True` sein)                                                                                                                                | Benutzer, Edition, Build **mit Revision** |
| S3      | Genau den **getesteten Commit** laden, nicht den Stand des Arbeitsordners. Der Commit-Hash wird im Protokoll festgehalten: `Invoke-WebRequest https://github.com/AndreZ1971/E.L.L.A.-Defence-Endpoint/archive/<COMMIT>.zip -OutFile C:\edep-run\edep.zip; Expand-Archive C:\edep-run\edep.zip C:\edep-run` | Commit, ZIP-Hash                          |
| S4      | `Get-FileHash` aller `.ps1`/`.psm1`/`.psd1` in `baseline\L1` nach `C:\edep-run\hashes.txt`                                                                                                                                                                                                                 | Datei                                     |
| S5      | Weiter mit **Phase A** (Abschnitt 4), im Ordner `C:\edep-run\E.L.L.A.-Defence-Endpoint-<COMMIT>\baseline\L1`                                                                                                                                                                                               |                                           |

**Getesteter Commit für den ersten Lauf:** `2ca9a435de47150d55128eb774f0c01fc8bf594c`
(Adresse also `…/archive/2ca9a435de47150d55128eb774f0c01fc8bf594c.zip`). Wurde das Repo seitdem geändert, ist der dann
aktuelle Hash zu nehmen und im Protokoll zu nennen.

### Abweichungen im Ablauf

| Phase              | Abweichung                                                                                                                                                                                                                                                                                                                |
| ------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| R-C10 (Neustart)   | In der Sandbox `Restart-Computer`. **Nicht** das Fenster schließen. Danach Transcript neu starten (`Start-Transcript -Append`).                                                                                                                                                                                           |
| R-C6 (Edge)        | Nur, wenn Edge in der Sandbox vorhanden ist; sonst als „ausgelassen“ mit Grund eintragen.                                                                                                                                                                                                                                 |
| R-C7 (Update)      | siehe oben                                                                                                                                                                                                                                                                                                                |
| Ergebnisse sichern | Das Mapping auf `C:\edep-out` ist ein Weg über die Sandbox-Anbindung, ob **die ausgehende Sperre ihn stört, ist ungeprüft**. Deshalb: Ergebnisse **erst nach Phase E** (also nach `Restore`) nach `C:\edep-out` kopieren. Steht dort nichts, per Zwischenablage in den Host kopieren, bevor das Fenster geschlossen wird. |
| Phase F            | Sandbox schließen, neu starten (= S0), Phase B bis C wiederholen                                                                                                                                                                                                                                                          |

> **Wichtig vor dem Schließen:** Phase E abgeschlossen, `C:\edep-run` vollständig nach `C:\edep-out` kopiert und auf dem
> Host in `E:\edep-results` sichtbar. Erst dann das Fenster schließen.

### Protokoll

Die Vorlage gilt unverändert; in der Zeile **Virtualisierung** steht „Windows-Sandbox“ und die Konfigurationsdatei.

### Gemessene Eigenschaften der Sandbox (Lauf 0, 2026-10-02)

| Eigenschaft              | Messwert                                                                                                              | Folge                                                                                                                                                                                              |
| ------------------------ | --------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Edition und Build        | Windows 11 Enterprise 24H2, 10.0.26100.9550 (Host: Pro for Workstations 26H2, 26300.9550)                             | werden in S2 gemessen, nicht angenommen                                                                                                                                                            |
| Allow-all-Regel          | `Container: allow outbound` (Programm, Dienst, Protokoll, Port, Adresse `Any`), **wird bei jedem Start neu angelegt** | nach **jedem** Start alle Regeln dieses Namens ausschalten: `Get-NetFirewallRule -DisplayName 'Container: allow outbound' \| Disable-NetFirewallRule`; Kontrolle mit `x.exe` (muss blockiert sein) |
| CiTool                   | Fehler `0x80073BC3`                                                                                                   | `-DeployAppControlAudit` nicht herstellbar; ID-01 bleibt FAIL                                                                                                                                      |
| Defender                 | `AntivirusEnabled False`                                                                                              | Defender-Prüfungen `UNKNOWN`, `Update-MpSignature` nicht prüfbar                                                                                                                                   |
| Windows Update           | `UsoSvc` deaktiviert, Fehler 0x8024002E und 0x80072EE6 schon vor EDEP                                                 | R-C7 und T-TEL-04a in der Sandbox nicht herstellbar                                                                                                                                                |
| Eingebundener Ordner     | `Copy-Item … C:\edep-out` blieb auch im Enforce-Modus ohne Fehlermeldung                                              | Ergebnisse lassen sich nach jeder Phase sichern; ich lese `E:\edep-results` direkt                                                                                                                 |
| Neustart aus der Sandbox | `Restart-Computer -Force`: Daten bleiben, EDEP-Einstellungen halten                                                   | R-C10 ist in der Sandbox ausführbar                                                                                                                                                                |
| Oberflächensprache       | Englisch (Rückfragen), Meldungen der Skripte deutsch                                                                  | kein Einfluss auf die Prüfungen                                                                                                                                                                    |
| Fingerabdruck            | `conformance/Get-EdepFingerprint.ps1`, in der Sandbox per Einfügen als `C:\edep-run\fp.ps1` angelegt                  | Hash des eingefügten Textes im Protokoll nennen                                                                                                                                                    |
