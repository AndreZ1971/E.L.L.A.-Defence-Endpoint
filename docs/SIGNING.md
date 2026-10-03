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

## Für den Herausgeber: so wird ein Release erzeugt

1. Alles committen, was ins Release gehört.
2. `python tools/make-checksums.py` erzeugt `SHA256SUMS` aus dem aktuellen Stand.
3. `ssh-keygen -Y sign -f <Schlüsseldatei> -n edep-release SHA256SUMS` erzeugt `SHA256SUMS.sig`.
4. `SHA256SUMS` und `SHA256SUMS.sig` committen (sie ändern keine andere Datei).
5. Tag signieren: `git -c gpg.format=ssh -c user.signingkey=<öffentlicher Schlüssel> tag -s <TAG> -m "<Text>"`, danach Commit und Tag pushen.

Der private Schlüssel gehört auf einen Rechner unter Kontrolle des Herausgebers, mit Passphrase, und in eine Sicherungskopie. Geht er
verloren oder wird er offengelegt, wird der Schlüssel bei GitHub entfernt, ein neuer angelegt und dieses Dokument mit Datum nachgeführt;
früher signierte Releases bleiben prüfbar, solange der öffentliche Schlüssel bekannt ist.
