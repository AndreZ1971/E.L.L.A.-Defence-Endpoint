# Selbst prüfen

Diese Anleitung ist für alle, die EDEP nicht glauben, sondern prüfen wollen. Jeder Schritt
nennt den Befehl und das erwartete Ergebnis. Weicht das Ergebnis ab, ist das ein Fehler in
EDEP: bitte als Issue melden ([SECURITY.md](../SECURITY.md) bei Sicherheitsrelevanz). Wer eine Messung als **Wiederholung** für das Projekt melden will, findet Ablauf und Meldeweg in [WIEDERHOLUNG.md](WIEDERHOLUNG.md).

**Grundregel:** Nichts davon auf einem Produktivrechner. Eine VM mit Snapshot genügt, z. B.
Windows 11 Enterprise als Evaluierungsversion oder Windows 11 Pro.

---

## Stufe 0: ein Aufruf für alles Lesende

Wer nur einen Befehl will: [Test-EdepConformance.ps1](../conformance/Test-EdepConformance.ps1) prüft die Integrität des Standes
([SIGNING.md](SIGNING.md)), die 15 L1-Anforderungen und das Audit und schreibt ein Protokoll als JSON. Es ändert nichts am System
und ist **kein Konformitätsnachweis** (die Tests „aktiv“ und „Review“ laufen nicht, sie stehen im Protokoll unter `notRun`).
Einzelheiten und Exit-Codes: [conformance/README.md](../conformance/README.md). Mit `-Destructive -ConfirmDestructive` führt das Skript in einer **Test-VM** zusätzlich
Install, Enforce, Umgehungstests und Restore aus (ändert das System, verweigert den Lauf ohne VM).

```powershell
# ZIP des Tags von GitHub laden, entpacken, als Administrator:
.\conformance\Test-EdepConformance.ps1 -Probe
```

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

> **Stand:** Zwei vollständige Durchläufe auf Hyper-V-VMs liegen vor: Windows 11 Enterprise 25H2
> ([Protokoll](../conformance/runs/2026-10-03-Enterprise25H2-26200.9550-HyperV/run.md)) und Windows 11 Pro 26H2
> ([Protokoll](../conformance/runs/2026-10-03-Pro26H2-26300.9457-HyperV/run.md)). Sie haben Mängel gefunden,
> die in den Erwartungen unten stehen. Windows Server ist nicht geprüft, Windows 11 Home nur einmal in einer VM (App Control ist dort nicht prüfbar, [E-94](EVIDENCE.md)); jeder Durchlauf eines Dritten
> ist ein Beitrag.
>
> **Vorbereitung auf einem frischen Windows:** Skripte sind gesperrt. Einmal pro PowerShell-Sitzung
> `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`. Rückfragen werden auf deutschem
> Windows mit **`J`** bestätigt (`A` = alle), auf englischem mit `y`; `-Confirm:$false` überspringt sie.

### 2.1 Anwenden und Konformität messen

```powershell
cd baseline\L1
.\Install-EdepL1.ps1 -DeployAppControlAudit -Enforce -AllowWindowsUpdate `
    -AllowProgram "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe"
.\Test-EdepL1.ps1
```

**Erwartung:** `EDEP 0.1.0 L1 — … — 15/15 erfüllt` (gemessen auf Enterprise 25H2). Auf Home/Pro ist
EDEP-TEL-01 `WARN`, weil „Diagnostic data off“ dort nicht existiert (SPEC Q-07); WARN zählt als
erfüllt. Ohne `-AllowWindowsUpdate` meldet EDEP-TEL-04 unter Enforce FAIL (14/15); mit der Option WARN („Wirkung nicht gemessen“), und `.\Test-EdepL1.ps1 -ProbeUpdates` misst sie.

### 2.2 Wirkung nachweisen, nicht nur Konfiguration

| Test                                 | Befehl                                                                                                          | Erwartung                            |
| ------------------------------------ | --------------------------------------------------------------------------------------------------------------- | ------------------------------------ |
| Unbekanntes Programm blockiert       | `copy C:\Windows\System32\curl.exe $env:TEMP\x.exe; & $env:TEMP\x.exe -m 5 https://example.org`                 | Fehler/Timeout                       |
| LOLBin blockiert                     | `curl.exe -m 5 https://example.org`                                                                             | Fehler/Timeout                       |
| Protokolliert                        | `Get-WinEvent -FilterHashtable @{LogName='Security'; Id=5157} -MaxEvents 5 \| Format-List TimeCreated, Message` | Einträge mit `x.exe` bzw. `curl.exe` |
| Erlaubtes Programm geht              | Edge öffnen, beliebige Seite                                                                                    | lädt                                 |
| Updates gehen                        | Einstellungen → Windows Update → Nach Updates suchen; `Update-MpSignature`                                      | **Ohne `-AllowWindowsUpdate`: scheitert** (`0x8024402F`/`0x80072EFD`, [E-74](EVIDENCE.md)). **Mit der Option:** gelingt nach höchstens drei Versuchen ([E-88](EVIDENCE.md)); Abweichungen bitte melden |
| Telemetrie blockiert                 | `Get-NetFirewallRule -Group EDEP-L1 \| ? DisplayName -like '*Telemetrie*' \| Get-NetFirewallServiceFilter`      | `DiagTrack`, `dmwappushservice`      |
| Hintertür per Benutzerpfad abgelehnt | `.\Install-EdepL1.ps1 -AllowProgram "$env:LOCALAPPDATA\Programs\…\app.exe" -WhatIf`                             | Abbruch mit EDEP-NET-10              |

### 2.3 Die bekannten Lücken selbst auslösen

EDEP behauptet nicht, alles zu verhindern. Die dokumentierten Umgehungen (SPEC 3.4) lassen
sich vorführen, und das Ergebnis muss **genau** der Beschreibung entsprechen:

```powershell
# B-01: BITS (gemessen: unter Enforce blockiert, Ursache offen), Protokoll prüfen
Start-BitsTransfer -Source https://example.org -Destination $env:TEMP\bits.html
Get-WinEvent -LogName Microsoft-Windows-Bits-Client/Operational -MaxEvents 5 |
    Where-Object Id -in 3, 59 | Format-List TimeCreated, Id, Message
```

**Gemessen (Sandbox und VM):** Die Übertragung **scheitert** („Die Serververbindung konnte nicht
hergestellt werden“), Ereignis 3 (Job angelegt) steht im Protokoll, Ereignis 59 nicht
([E-71](EVIDENCE.md)). Die Spezifikation (SPEC 3.4, B-01) sagt dazu, was belegt ist. Gelingt sie bei
dir, ist das eine neue Messung und bitte zu melden.

### 2.4 Rücknahme prüfen

```powershell
.\Restore-EdepL1.ps1
.\Test-EdepL1.ps1   # wieder die ursprünglichen FAIL-Ergebnisse (7/15 im Ausgangszustand mit Sicherungen)
```

Früher kam in zwei von fünf Versuchen der EDEP-Zustand nach dem Neustart zurück; nach einem **harten** Neustart direkt nach der Rücknahme kam zuletzt der Telemetriewert zurück ([E-76](EVIDENCE.md)). Starte nach der Rücknahme **ordentlich** neu.
Prüfe daher nach der Rücknahme und einem Neustart noch einmal.

`Restore-EdepL1.ps1` ohne `-BackupPath` nimmt die **älteste** Sicherung, also den Zustand vor der ersten Anwendung überhaupt. Hast du EDEP schon früher angewendet (Ordner `C:\ProgramData\EDEP\backup` enthält mehrere Sicherungen), kann sich der Zustand danach in einzelnen Firewallregeln vom Zustand direkt vor dieser Anwendung unterscheiden ([E-91](EVIDENCE.md)). Willst du genau diesen Stand, gib `-BackupPath` mit dem Ordner der Sicherung an, die der Installer beim letzten Mal ausgegeben hat.

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
