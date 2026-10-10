# Signierte Releases und Prüfsummen

Ab dem Tag `0.1.0-draft.3` tragen Releases eine Datei `SHA256SUMS` (SHA-256 aller Dateien des Standes) mit einer SSH-Signatur
`SHA256SUMS.sig`. Der Git-Tag ist ebenfalls mit demselben Schlüssel signiert. Damit lässt sich prüfen, dass ein heruntergeladener
Stand unverändert ist und von diesem Schlüssel stammt.

**Was die Signatur zeigt, und was nicht.** Sie zeigt, dass die Dateien seit dem Signieren nicht verändert wurden und dass der
Besitzer des Schlüssels sie so freigegeben hat. Sie sagt **nichts** darüber, ob der Inhalt richtig oder sicher ist. Sie ersetzt auch
**keine Authenticode-Signatur der Skripte**: SYS.2.2.3.A22 (IT-Grundschutz) verlangt für erhöhten Schutzbedarf die Ausführungsrichtlinie
`AllSigned`; dafür fehlt ein von Prüfern anerkanntes Zertifikat (siehe [BSI-MAPPING.md](BSI-MAPPING.md)). Die PowerShell-Skripte sind
**weiterhin nicht Authenticode-signiert**.

## Der Schlüssel

| | |
|---|---|
| Zweck | ausschließlich Signatur der EDEP-Releases (nicht für Server oder Anmeldung) |
| Typ | ED25519 |
| Fingerabdruck | `SHA256:26hgKYeEbL+2ryTJ2Q5Otc/Af93f+8ModNBheF2/pas` |
| Öffentlicher Schlüssel | `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFeMSqmz3eSz0NgR9O7gDr/+C6b4Yi+eAzaTFgWdjrEb` |
| Bei GitHub hinterlegt als | „Signing Key“ des Kontos `AndreZ1971` (hinterlegt am 2026-10-03) |

**Vertrauensanker.** Die Datei `allowed_signers` im Repository enthält diesen Schlüssel, ist aber **kein** unabhängiger Beleg:
Wer das Repository verändert, könnte auch sie ändern. Vergleiche deshalb den Fingerabdruck mit einer zweiten Quelle:
`https://api.github.com/users/AndreZ1971/ssh_signing_keys` (öffentlich, ohne Anmeldung abrufbar) und mit diesem Dokument aus einem
Stand, dem du bereits vertraust.

## Prüfen

Lade den **ZIP-Stand des Tags** von GitHub (`https://github.com/AndreZ1971/E.L.L.A.-Defence-Endpoint/archive/refs/tags/<TAG>.zip`)
und entpacke ihn. Ein `git clone` unter Windows wandelt Zeilenenden um (`core.autocrlf`) und liefert dann andere Hashes. Die Prüfsummen
gelten für den ZIP-Stand und für `git -c core.autocrlf=false -c core.eol=lf archive <TAG>`.

**1. Signatur der Prüfsummen** (Linux, macOS, Git Bash, Windows 10/11 mit OpenSSH):

```
ssh-keygen -Y verify -f allowed_signers -I edep-release -n edep-release -s SHA256SUMS.sig < SHA256SUMS
```

Erwartet: `Good "edep-release" signature for edep-release with ED25519 key SHA256:26hgKYeEbL+2ryTJ2Q5Otc/Af93f+8ModNBheF2/pas`.

**2. Hashes aller Dateien** (Linux, macOS, Git Bash):

```
sha256sum -c SHA256SUMS
```

(`SHA256SUMS` und `SHA256SUMS.sig` stehen nicht in der Liste.) Unter PowerShell:

```
Get-Content SHA256SUMS | ForEach-Object {
    $h, $p = $_ -split '  ', 2
    $ok = (Get-FileHash -Algorithm SHA256 -LiteralPath $p).Hash -eq $h.ToUpper()
    '{0}  {1}' -f $(if ($ok) { 'OK     ' } else { 'FALSCH ' }), $p
} | Where-Object { $_ -notlike 'OK*' }
```

Keine Ausgabe bedeutet: alle Hashes stimmen.

**3. Signierter Tag** (nur im Git-Klon):

```
git -c gpg.ssh.allowedSignersFile=allowed_signers tag -v <TAG>
```

## Bitcoin-Zeitstempel (OpenTimestamps)

Zusätzlich zur Signatur wird `SHA256SUMS` mit [OpenTimestamps](https://opentimestamps.org) in der Bitcoin-Blockchain verankert
(je Release eine Datei `timestamps/SHA256SUMS-<TAG>.ots`). Das belegt unabhängig von GitHub und vom Herausgeber, dass genau dieser Stand **spätestens zum Zeitpunkt des
Blocks** existierte. Es sagt nichts über die Richtigkeit des Inhalts. Gesendet wird nur ein Hash, nie Dateiinhalt.

Der Zeitstempel kommt **nach** dem signierten Tag in einem eigenen Commit (er kann nicht Teil des Standes sein, den er bestätigt).
Er ist zunächst **ausstehend**; nach einigen Stunden wird er mit `upgrade` um die Bitcoin-Bestätigung ergänzt.

**Prüfen** (eine der drei Möglichkeiten):

```
ots verify timestamps/SHA256SUMS-<TAG>.ots                  # Standardclient (pip install opentimestamps-client), braucht einen Bitcoin-Zugang
python tools/ots.py verify SHA256SUMS timestamps/SHA256SUMS-<TAG>.ots   # nur pip install opentimestamps; prüft über die öffentliche Blockstream-API
```

oder `SHA256SUMS` und die `.ots`-Datei auf https://opentimestamps.org hochladen. `SHA256SUMS` ist dabei die Datei **des Tags** (aus dem ZIP des Tags), die `.ots`-Datei kommt aus dem Ordner `timestamps/` auf `main`; sie wird erst nach dem Tag hinzugefügt und ist deshalb nicht im ZIP des eigenen Releases. Erwartet: ein Bitcoin-Block mit Höhe und Zeit.
`tools/ots.py` hat zusätzlich `stamp DATEI` (zeitstempeln) und `upgrade DATEI.ots` (Bestätigung nachholen).

**Ablage.** Bis `0.1.0-draft.4` lag die Datei als `SHA256SUMS.ots` im Wurzelordner. Weil sie in die Prüfsummen des nächsten Standes einging, enthält das ZIP von `0.1.0-draft.5` im Wurzelordner noch diese Datei; **sie gehört zu draft.4** und passt nicht zur `SHA256SUMS` von draft.5. Seit draft.5 liegt je Release eine Datei unter `timestamps/`.

## Geprüfte Releases

| Tag | Commit | Dateien in `SHA256SUMS` | Geprüft am | Ergebnis |
| --- | --- | --- | --- | --- |
| `0.1.0-draft.3` | `6d5556c` | 120 | 2026-10-03 | Signatur gültig, 120 von 120 Hashes, Tag bei GitHub „Verified“, Schlüssel in der GitHub-Liste |
| `0.1.0-draft.4` | `d1975c8` | 141 | 2026-10-04 | Signatur gültig, 141 von 141 Hashes, Tag bei GitHub „Verified“, Schlüssel in der GitHub-Liste; `Test-EdepConformance.ps1` auf dem ZIP-Stand meldet `Prüfsummen PASS` und `Signatur PASS` |

| `0.1.0-draft.5` | `60a2547` | 172 | 2026-10-10 | Signatur gültig, 172 von 172 Hashes, Tag bei GitHub „Verified“ (Grund `valid`), Schlüssel in der GitHub-Liste; `Test-EdepConformance.ps1` auf dem ZIP-Stand meldet `Prüfsummen PASS` und `Signatur PASS` |

Die Prüfung erfolgte jeweils am heruntergeladenen ZIP des Tags, nicht am lokalen Arbeitsordner.

Zeitstempel `0.1.0-draft.5`: am 2026-10-10 bei vier Kalendern eingereicht, **ausstehend** (`timestamps/SHA256SUMS-0.1.0-draft.5.ots`, SHA-256 der Prüfsummen `7e1dcd6f1cc94b4464639d696473189ab6dec575f753bc4b3795fb2291f393d2`); die Bestätigung wird nach einigen Stunden nachgetragen.

Zeitstempel: `0.1.0-draft.4` am 2026-10-04 bei vier Kalendern eingereicht und **in Bitcoin-Block 969890 bestätigt** (Blockzeit 2026-10-04 19:35:29 UTC; Blockhash `00000000000000000001f9e68e09444640488e0b12c57ecc06fa7d79df87bedf`, mit zwei unabhängigen Block-Schnittstellen abgeglichen). Zwei Kalender (catallaxy, eternitywall) waren zum Zeitpunkt der Prüfung noch ausstehend. Prüfen: `python tools/ots.py verify SHA256SUMS SHA256SUMS.ots`. Der Beweis lautet: Dieser Stand von `SHA256SUMS` existierte spätestens zur Blockzeit.

## Für den Herausgeber: so wird ein Release erzeugt

1. Alles committen, was ins Release gehört.
2. `python tools/make-checksums.py` erzeugt `SHA256SUMS` aus dem aktuellen Stand.
3. `ssh-keygen -Y sign -f <Schlüsseldatei> -n edep-release SHA256SUMS` erzeugt `SHA256SUMS.sig`.
4. `SHA256SUMS` und `SHA256SUMS.sig` committen (sie ändern keine andere Datei).
5. Tag signieren: `git -c gpg.format=ssh -c user.signingkey=<öffentlicher Schlüssel> tag -s <TAG> -m "<Text>"`, danach Commit und Tag pushen.
6. Nach dem Push: `python tools/ots.py stamp SHA256SUMS`, die entstandene `SHA256SUMS.ots` nach `timestamps/SHA256SUMS-<TAG>.ots` verschieben und in einem eigenen Commit festhalten; einige Stunden später `python tools/ots.py upgrade timestamps/SHA256SUMS-<TAG>.ots` und die vervollständigte Datei erneut committen.

Der private Schlüssel gehört auf einen Rechner unter Kontrolle des Herausgebers, mit Passphrase, und in eine Sicherungskopie. Geht er
verloren oder wird er offengelegt, wird der Schlüssel bei GitHub entfernt, ein neuer angelegt und dieses Dokument mit Datum nachgeführt;
früher signierte Releases bleiben prüfbar, solange der öffentliche Schlüssel bekannt ist.
