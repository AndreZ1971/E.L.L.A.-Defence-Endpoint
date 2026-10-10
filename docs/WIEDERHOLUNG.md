# Eine Messung wiederholen (für Dritte)

Diese Seite ist für Personen **außerhalb des Projekts**, die die Messungen von EDEP L1 in einer eigenen Umgebung wiederholen wollen. Jede Wiederholung zählt, auch wenn sie ein anderes Ergebnis liefert als wir. Gesucht ist, was **abweicht**.

**Zeitaufwand:** etwa eine Stunde, ohne die Einrichtung der VM. **Stand der Anleitung:** Release `0.1.0-draft.6` (Entwurf, kein Konformitätsnachweis, keine Unterstützung durch das BSI).

## Was „unabhängig“ heißt

Du hast an der Entwicklung, den Tests und der Dokumentation von EDEP nicht mitgewirkt. Das ist die Bedingung dafür, dass eine Wiederholung als unabhängig geführt wird ([ROADMAP, K3](ROADMAP.md)). Eine Wiederholung ohne diese Bedingung ist trotzdem willkommen, wird nur anders eingeordnet.

## Wichtig vorab

- **Nur in einer Test-VM, nie auf einem Rechner, den du brauchst.** Stufe 2 ändert Firewall, Richtlinien und Überwachung und nimmt sie wieder zurück. Die Stufe verweigert den Lauf, wenn sie keine virtuelle Maschine erkennt.
- **Lege vor dem Start einen Prüfpunkt (Snapshot) an.** Dann kannst du jederzeit zurück.
- Eine **frische Windows-11-Installation** ist am besten. Gemessen haben wir bisher Windows 11 **Enterprise**, **Pro** und **Home** (Build 26300, 26H2) in Hyper-V. Andere Editionen und andere Hypervisoren (VirtualBox, VMware, KVM) sind ausdrücklich willkommen; nenne sie in der Meldung.
- **Lass Windows Update erst fertig laufen** und notiere den Build danach (`winver`). Auf Home lässt sich das Update nicht abschalten; es hat bei uns während einer Messung den Build gewechselt und die Zahl der Firewallregeln verändert ([E-96](EVIDENCE.md)).

## Ablauf

**1. Den Release holen.** Lade das ZIP des Tags `0.1.0-draft.6` von GitHub (`https://github.com/AndreZ1971/EDEP/archive/refs/tags/0.1.0-draft.6.zip`) und entpacke es in der VM. **Kein `git clone`:** Unter Windows wandelt es Zeilenenden um, dann stimmen die Prüfsummen nicht.

**2. Integrität prüfen** (Administrator-PowerShell im entpackten Ordner):

```powershell
Set-ExecutionPolicy -Scope Process Bypass -Force
.\conformance\Test-EdepConformance.ps1
```

Erwartet: `PASS Prüfsummen` und `PASS Signatur`. Das setzt `ssh-keygen` voraus (in Windows 11 meist als „OpenSSH-Client“ vorhanden). Ändert nichts am System. Die übrigen Zeilen zeigen den Ausgangszustand deiner VM (ohne EDEP erfüllt ein Windows etwa 6 bis 7 der 15 Prüfungen; das ist normal).

**3. Prüfpunkt anlegen** (jetzt, nicht später).

**4. Die Stufe „Destructive“ ausführen** (ändert die VM und nimmt zurück):

```powershell
.\conformance\Test-EdepConformance.ps1 -Destructive -ConfirmDestructive
```

Erwartet (so haben wir es gemessen): 13 Schritte `D-A1` bis `D-E1`, alle `PASS`, am Ende die Zeile „Bitte jetzt ordentlich neu starten“. Auf **Windows 11 Home** fehlt die App-Control-Vorlage; die Stufe läuft dann ohne `-DeployAppControlAudit` und weist darauf hin ([E-94](EVIDENCE.md)). Der Exit-Code 1 ist normal, weil der Ausgangszustand nicht gehärtet ist.

**5. Neu starten und prüfen:** ordentlich neu starten (nicht ausschalten), dann `.\baseline\L1\Test-EdepL1.ps1`. Erwartet: dieselbe Zahl erfüllter Prüfungen wie vor Schritt 4.

**6. Optional:** die Wirkungs- und Umgehungstests aus [VERIFY-YOURSELF.md](VERIFY-YOURSELF.md), Stufe 2.

## Was du einsendest

Eröffne ein [Issue mit der Vorlage „Wiederholung melden“](https://github.com/AndreZ1971/EDEP/issues/new?template=wiederholung.yml) und hänge an:

1. **Das Protokoll** `edep-conformance-<Rechner>-<Datum>.json` aus Schritt 4. Es enthält den **Rechnernamen**. Ersetze ihn vor dem Hochladen durch einen beliebigen Namen, wenn du ihn nicht veröffentlichen willst.
2. **Edition und Build** (`winver`), die **Art der VM** (Hypervisor und Version).
3. **Alles, was von den Erwartungen oben abweicht**, mit dem **Wortlaut** der Ausgabe statt deiner Deutung. Ein „es hat nicht geklappt“ ohne Meldung kann ich nicht auswerten.
4. Ob du **unabhängig** bist (siehe oben).

Schicke **keine Kennwörter, Schlüssel oder Kontodaten** und nichts aus einer echten Umgebung. Mit dem Einsenden erlaubst du, die Angaben im Repository zu veröffentlichen, auf Wunsch ohne deinen Namen.

## Was wir damit tun

Wir prüfen die Meldung, legen sie mit Prüfsumme als Protokoll unter `conformance/runs/` ab (Name nur mit deinem Einverständnis) und tragen das Ergebnis in das [Belegregister](EVIDENCE.md) ein, **auch dann, wenn es unseren Messungen widerspricht**. Was als Widerlegung gilt, steht in [VERIFY-YOURSELF.md](VERIFY-YOURSELF.md), Abschnitt „Was als Widerlegung gilt“.

## Bekannte Stolpersteine

- **Windows 11 Home:** keine App-Control-Vorlage (Stufe läuft im Home-Modus), keine Zwischenablage zur VM, die Einrichtung ohne Microsoft-Konto braucht einen Umweg (`start ms-cxh:localonly` in der Eingabeaufforderung mit Umschalt+F10). In der Konsole der VM kann man die Zahl der erlaubenden Firewallregeln kurz nach einem Neustart wachsen sehen, auch ohne EDEP ([E-96](EVIDENCE.md)).
- **Windows Update** kann während der Messung Neustarts und neue Regeln auslösen. Notiere den Build vor und nach dem Lauf.
- **Nicht gemessen** ist die Wirkung unter Windows 10, Windows Server, auf echter Hardware, mit anderen Sprachen als Deutsch und mit fremdem Virenschutz ([SPEC 3.6](../SPEC.md)). Die Ausgabe der Skripte ist deutsch.
