# E.D. Endpoint Profile (EDEP)

**Offenes Sicherheitsprofil für Windows-Endgeräte: Outbound-Zero-Trust, Telemetrie-Souveränität und deterministische Isolation.**

EDEP legt fest, was ein Windows-Rechner technisch erzwingen muss, damit gilt:

- Kein Programm spricht ins Netz, das nicht ausdrücklich dafür zugelassen ist.
- Das Betriebssystem überträgt nur die unvermeidliche Telemetrie, und der Nutzer sieht das.
- Jede Blockade ist lokal protokolliert.
- Bei erkanntem Datenabfluss isoliert sich der Host, deterministisch und nicht auf Modellverdacht.

EDEP ist **kein Antivirus**. Es ist als Ergänzung zu Microsoft Defender oder einem anderen AV-Produkt
gedacht.

> **Status:** Entwurf 0.1.0. Die Spezifikation ist noch nicht versiegelt.

## Kostenloses Audit: Wie offen ist dein Windows?

Windows lässt ausgehenden Verkehr standardmäßig für jedes Programm zu, auch mit Defender.
Das Audit zeigt in einer Minute, was davon auf deinem Rechner zutrifft. Es **ändert nichts**
und läuft auch ohne Adminrechte.

```powershell
# Im Ordner baseline\L1 (für das vollständige Ergebnis als Administrator)
.\Invoke-EdepAudit.ps1 -Open
```

Ergebnis: eine Punktzahl von 0 bis 100, Kategorien (ausgehender und eingehender Verkehr,
Programmkontrolle, Telemetrie, Protokollierung, Angriffsfläche) und für jeden offenen Punkt
eine Erklärung mit konkreter Empfehlung, in der Konsole und als HTML-Bericht.

## Nicht glauben, prüfen

| Frage                                       | Antwort                                                                                                                                                 |
| ------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Stimmt das, was hier steht?                 | Jede technische Aussage hat eine Quelle oder einen Messwert: [Nachweisregister](docs/EVIDENCE.md). Was noch nicht geprüft ist, steht dort offen als ⏳. |
| Woher stammen die Fakten?                   | 26 verlinkte Quellen, überwiegend Microsoft Learn und MITRE ATT&CK: [SPEC, Anhang B](SPEC.md#anhang-b--quellen)                                         |
| Was kann EDEP **nicht**?                    | Restrisiken und sieben bekannte Umgehungen, jede mit Test: [SPEC 3.3/3.4](SPEC.md#34-bekannte-umgehungen-normativ)                                      |
| Wo weicht EDEP von Microsoft ab, und warum? | [DD-12](docs/DESIGN-DECISIONS.md)                                                                                                                       |
| Wie prüfe ich es selbst?                    | In 5 Minuten ohne Risiko, in 30 Minuten in einer VM: [Selbst prüfen](docs/VERIFY-YOURSELF.md)                                                           |
| Welche Fehler gab es schon?                 | [Errata](docs/EVIDENCE.md#errata)                                                                                                                       |
| Ich habe eine Lücke gefunden.               | [SECURITY.md](SECURITY.md)                                                                                                                              |

## Stufen

| Stufe           | Umsetzung                                                                            | Eigener Code                  |
| --------------- | ------------------------------------------------------------------------------------ | ----------------------------- |
| **L1 Baseline** | Nur Windows-Bordmittel (Firewall, App Control, Richtlinien)                          | nein, [Skripte](baseline/L1/) |
| **L2 Enforced** | Agent mit WFP-Filtern, Programmidentität per Signatur/Hash, Boot-Time-Filter         | ja, ohne Kernel-Treiber       |
| **L3 Isolated** | Deterministische Notfall-Isolation, Metadaten-Anomalieerkennung, Modell nur beratend | ja                            |

## Schnellstart L1

In einer **PowerShell als Administrator** im Ordner `baseline\L1`:

```powershell
# 1. Nur anzeigen, was passieren würde
.\Install-EdepL1.ps1 -DeployAppControlAudit -WhatIf

# 2. Im Audit-Modus anwenden (ausgehend bleibt noch erlaubt, alles wird protokolliert)
.\Install-EdepL1.ps1 -DeployAppControlAudit

# 3. Prüfen
.\Test-EdepL1.ps1

# 4. Nach Auswertung des Firewall-Logs: ausgehend standardmäßig blockieren
.\Install-EdepL1.ps1 -Enforce -DeployAppControlAudit `
    -AllowProgram "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe"

# Rückgängig (stellt den Zustand vor der ersten Anwendung her)
.\Restore-EdepL1.ps1
```

**Achtung bei `-Enforce`:** Danach haben nur noch Programme mit Erlaubnisregel
Netzzugang: Windows-Kernnetzwerk, Update-Dienste, Defender und die unter `-AllowProgram`
genannten Programme. Store-Apps behalten ihre eigenen Windows-Regeln. PowerShell,
`curl.exe`, `certutil` und andere Anhang-A-Werkzeuge sind ausgehend gesperrt, auch für
`Install-Module` und `winget`-Skripte.

Die Blocklisten stützen sich zum Teil auf Programmpfade. Wird eine Richtlinie per
Gruppenrichtlinie oder Intune verteilt, überschreibt diese die lokalen Einstellungen.
`Test-EdepL1.ps1` prüft deshalb immer den **wirksamen** Zustand.

## Inhalt

| Pfad                                                             | Inhalt                                                                  |
| ---------------------------------------------------------------- | ----------------------------------------------------------------------- |
| [SPEC.md](SPEC.md)                                               | Normative Spezifikation: Bedrohungsmodell, Anforderungen, Stufen        |
| [conformance/](conformance/README.md)                            | Konformitätstests je Anforderung                                        |
| [baseline/L1/](baseline/L1/)                                     | Audit sowie Anwenden, Prüfen und Wiederherstellen für L1 (Modul `EDEP`) |
| [tools/](tools/)                                                 | Modul bauen, signieren, Richtlinien validieren                          |
| [schema/edep-policy.schema.json](schema/edep-policy.schema.json) | Richtliniensprache (JSON Schema)                                        |
| [examples/policy.example.yaml](examples/policy.example.yaml)     | Beispielrichtlinie                                                      |
| [docs/DESIGN-DECISIONS.md](docs/DESIGN-DECISIONS.md)             | Warum EDEP so gebaut ist, und was vom ersten Konzept korrigiert wurde   |
| [docs/L2-AGENT-ARCHITECTURE.md](docs/L2-AGENT-ARCHITECTURE.md)   | Referenzarchitektur für den L2-Agenten                                  |
| [docs/ROADMAP.md](docs/ROADMAP.md)                               | Meilensteine                                                            |
| [docs/archive/](docs/archive/)                                   | Ursprüngliche Konzeptpapiere (nicht mehr gültig)                        |

## Was EDEP nicht leistet

Angreifer mit Administrator- oder Kernel-Rechten, Inhalte verschlüsselter Verbindungen,
Missbrauch zugelassener Programme und kompromittierte signierte Software liegen außerhalb
des Geltungsbereichs. Details stehen in [SPEC.md, Abschnitt 3.3](SPEC.md#33-ausdrücklich-nicht-im-geltungsbereich-restrisiken).
Diese Grenzen sind Teil der Norm und dürfen in keiner Produktbeschreibung fehlen.

## Lizenz

[MIT](LICENSE)
