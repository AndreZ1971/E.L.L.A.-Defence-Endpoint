# Selbst prüfen

Diese Anleitung ist für alle, die EDEP nicht glauben, sondern prüfen wollen. Jeder Schritt
nennt den Befehl und das erwartete Ergebnis. Weicht das Ergebnis ab, ist das ein Fehler in
EDEP: bitte als Issue melden ([SECURITY.md](../SECURITY.md) bei Sicherheitsrelevanz).

**Grundregel:** Nichts davon auf einem Produktivrechner. Eine VM mit Snapshot genügt, z. B.
Windows 11 Enterprise als Evaluierungsversion oder Windows 11 Pro.

---

## Stufe 1: fünf Minuten, ohne Risiko

Auf jedem Windows-Rechner, ohne Adminrechte. Es wird nichts verändert.

```powershell
git clone https://github.com/AndreZ1971/E.L.L.A.-Defence-Endpoint
cd E.L.L.A.-Defence-Endpoint\baseline\L1
.\Invoke-EdepAudit.ps1 -Open
```

**Erwartung auf einem ungehärteten Windows:**

- „Ausgehender Verkehr standardmäßig blockiert“ = **Offen**. Das ist die Kernaussage von EDEP:
  Windows lässt jedes Programm hinaus. Gegenprobe ohne EDEP:
  `Get-NetFirewallProfile -PolicyStore ActiveStore | Select Name, DefaultOutboundAction` → `Allow`.
- Drei Punkte „Nicht prüfbar“ (App Control, Defender-Einstellungen), weil ohne Adminrechte.

**Dass das Audit nichts ändert, prüfen:** Vorher und nachher vergleichen.

```powershell
netsh advfirewall export "$env:TEMP\vorher.wfw"
.\Invoke-EdepAudit.ps1 -NoHtml
netsh advfirewall export "$env:TEMP\nachher.wfw"
(Get-FileHash "$env:TEMP\vorher.wfw").Hash -eq (Get-FileHash "$env:TEMP\nachher.wfw").Hash   # True
```

Der Code ist kurz genug, um ihn ganz zu lesen: [EdepL1.Checks.ps1](../baseline/L1/EdepL1.Checks.ps1)
und [EdepAudit.ps1](../baseline/L1/EdepAudit.ps1) enthalten nur lesende Aufrufe.

---

## Stufe 2: dreißig Minuten in einer VM

PowerShell **als Administrator**, Snapshot vorher anlegen.

> **Stand:** Stufe 2 hat das Projekt selbst noch nicht vollständig auf einer VM durchlaufen
> ([EVIDENCE.md](EVIDENCE.md), E-63 und E-64 sind ⏳). Die Erwartungen unten sind aus
> Spezifikation und Quellen abgeleitet. Das erste vollständige Protokoll wird unter
> `conformance/runs/` veröffentlicht. Bis dahin ist jeder Durchlauf eines Dritten ein Beitrag.

### 2.1 Anwenden und Konformität messen

```powershell
cd baseline\L1
.\Install-EdepL1.ps1 -DeployAppControlAudit -Enforce `
    -AllowProgram "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe"
.\Test-EdepL1.ps1
```

**Erwartung:** `EDEP 0.1.0 L1 — … — 15/15 erfüllt`. Auf Home/Pro ist EDEP-TEL-01 `WARN`,
weil „Diagnostic data off“ dort nicht existiert (SPEC Q-07); WARN zählt als erfüllt.

### 2.2 Wirkung nachweisen, nicht nur Konfiguration

| Test                                 | Befehl                                                                                                          | Erwartung                            |
| ------------------------------------ | --------------------------------------------------------------------------------------------------------------- | ------------------------------------ |
| Unbekanntes Programm blockiert       | `copy C:\Windows\System32\curl.exe $env:TEMP\x.exe; & $env:TEMP\x.exe -m 5 https://example.org`                 | Fehler/Timeout                       |
| LOLBin blockiert                     | `curl.exe -m 5 https://example.org`                                                                             | Fehler/Timeout                       |
| Protokolliert                        | `Get-WinEvent -FilterHashtable @{LogName='Security'; Id=5157} -MaxEvents 5 \| Format-List TimeCreated, Message` | Einträge mit `x.exe` bzw. `curl.exe` |
| Erlaubtes Programm geht              | Edge öffnen, beliebige Seite                                                                                    | lädt                                 |
| Updates gehen                        | Einstellungen → Windows Update → Nach Updates suchen; `Update-MpSignature`                                      | erfolgreich                          |
| Telemetrie blockiert                 | `Get-NetFirewallRule -Group EDEP-L1 \| ? DisplayName -like '*Telemetrie*' \| Get-NetFirewallServiceFilter`      | `DiagTrack`, `dmwappushservice`      |
| Hintertür per Benutzerpfad abgelehnt | `.\Install-EdepL1.ps1 -AllowProgram "$env:LOCALAPPDATA\Programs\…\app.exe" -WhatIf`                             | Abbruch mit EDEP-NET-10              |

### 2.3 Die bekannten Lücken selbst auslösen

EDEP behauptet nicht, alles zu verhindern. Die dokumentierten Umgehungen (SPEC 3.4) lassen
sich vorführen, und das Ergebnis muss **genau** der Beschreibung entsprechen:

```powershell
# B-01: BITS umgeht die Programmsperre (bekannt), wird aber protokolliert
Start-BitsTransfer -Source https://example.org -Destination $env:TEMP\bits.html
Get-WinEvent -LogName Microsoft-Windows-Bits-Client/Operational -MaxEvents 5 |
    Where-Object Id -in 3, 59 | Format-List TimeCreated, Id, Message
```

**Erwartung:** Die Übertragung **gelingt**, Ereignis 3 (Job mit Besitzer) und 59 (URL) stehen
im Protokoll. Gelingt sie **nicht**, ist die Dokumentation falsch, auch das bitte melden.

### 2.4 Rücknahme prüfen

```powershell
.\Restore-EdepL1.ps1
.\Test-EdepL1.ps1   # wieder die ursprünglichen FAIL-Ergebnisse
```

Snapshot zurücksetzen.

---

## Stufe 3: die Aussagen selbst

- **Jede Quelle ist verlinkt:** [SPEC.md, Anhang B](../SPEC.md#anhang-b--quellen).
  28 Quellen, fast alle Herstellerdokumentation (Microsoft Learn) oder MITRE ATT&CK.
- **Jede Aussage hat einen Status:** [EVIDENCE.md](EVIDENCE.md). Was nicht geprüft ist,
  steht dort als ⏳, mit Prüfweg.
- **Jede Abweichung von Microsoft ist begründet:** [DESIGN-DECISIONS.md, DD-12](DESIGN-DECISIONS.md).
- **Jeder korrigierte Fehler ist verzeichnet:** [EVIDENCE.md, Errata](EVIDENCE.md#errata).

## Was als Widerlegung gilt

EDEP gilt in einem Punkt als widerlegt, wenn eines davon reproduzierbar gelingt:

1. Ein Test aus [conformance/README.md](../conformance/README.md) liefert auf einem konform
   gemeldeten System ein anderes Ergebnis als erwartet.
2. Ein Programm ohne Freigabe erreicht im Enforce-Modus das Netz auf einem Weg, der **nicht**
   in SPEC 3.3 oder 3.4 steht.
3. Eine Quelle in Anhang B sagt nicht, was EDEP ihr zuschreibt.
4. Das Audit verändert den Systemzustand.

Solche Befunde sind willkommen und werden in [EVIDENCE.md](EVIDENCE.md#errata) mit Dank
verzeichnet.
