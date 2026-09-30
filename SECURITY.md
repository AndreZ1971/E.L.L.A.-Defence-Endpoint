# Sicherheitsrichtlinie

## Schwachstellen melden

Bitte **keine öffentlichen Issues** für Schwachstellen, die EDEP-geschützte Systeme gefährden
(z. B. eine Umgehung, die nicht in [SPEC.md, Abschnitt 3.3/3.4](SPEC.md#34-bekannte-umgehungen-normativ)
steht, oder ein Fehler, durch den Install/Restore das System ungeschützt zurücklässt).

Stattdessen über GitHub: **Security → Report a vulnerability** (Private Vulnerability Reporting)
in diesem Repository.

Bitte angeben:

- EDEP-Version und Stufe, Windows-Edition und Build (`winver`)
- Schritte zur Reproduktion, erwartetes und tatsächliches Ergebnis
- Ausgabe von `Test-EdepL1.ps1 -Json`, sofern relevant

## Ablauf

| Schritt                                           | Ziel                                                                                                           |
| ------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- |
| Eingangsbestätigung                               | innerhalb von 5 Werktagen                                                                                      |
| Erste Bewertung                                   | innerhalb von 14 Tagen                                                                                         |
| Behebung oder Dokumentation als bekannte Umgehung | abhängig vom Schweregrad, mit Rückmeldung                                                                      |
| Veröffentlichung                                  | koordiniert, mit Nennung der meldenden Person (falls gewünscht) in [docs/EVIDENCE.md](docs/EVIDENCE.md#errata) |

## Keine Schwachstelle

Diese Punkte sind bekannte, dokumentierte Grenzen und kein Sicherheitsvorfall:

- alles in SPEC 3.3 (R1–R6) und 3.4 (B-01–B-07)
- Microsoft-Verhalten, das EDEP bewusst anders konfiguriert (DD-12)

Neue Wege um EDEP herum sind ausdrücklich erwünscht, auch wenn sie in eine dieser
Kategorien fallen, aber einen neuen Mechanismus nutzen.
