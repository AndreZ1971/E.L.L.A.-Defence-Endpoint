# Änderungsprotokoll

Format angelehnt an [Keep a Changelog](https://keepachangelog.com/de/1.1.0/).
Korrekturen an der Spezifikation stehen zusätzlich mit Begründung in
[docs/EVIDENCE.md, Errata](docs/EVIDENCE.md#errata).

## [Unveröffentlicht]

### Hinzugefügt

- `Invoke-EdepAudit`: kostenloses Audit mit Punktzahl, Erklärungen und HTML-Bericht, auch ohne Adminrechte
- PowerShell-Modul `EDEP` (Manifest, Build- und Signierskript)
- SPEC 3.4 „Bekannte Umgehungen“ (B-01 bis B-07) mit Umgehungstests T-BYP-01 bis T-BYP-07
- EDEP-NET-10: Freigaben nur für admin-geschützte Programmpfade
- EDEP-LOG-06: BITS-Clientprotokoll als Erkennung für B-01
- Quellenverzeichnis (SPEC Anhang B, 26 Quellen), Nachweisregister (`docs/EVIDENCE.md`),
  Prüfanleitung (`docs/VERIFY-YOURSELF.md`), `SECURITY.md`
- DD-11 (Programmidentität per App-Control-AppID-Tags prüfen), DD-12 (bewusste Abweichungen von Microsoft)
- CI: Syntax, BOM, PSScriptAnalyzer, Rauchtests, Schema-Validierung mit Negativtests
- Roadmap

### Korrigiert

- **EDEP-NET-08:** Boot-Time- und persistente Filter sind getrennte Sätze; die Flags sind laut
  Microsoft nicht kombinierbar. Provider muss an einen auto-startenden Dienst gebunden sein.
- **EDEP-NET-07:** Sublayer mit höchstem Gewicht; hard permit in höherem Sublayer als Risiko benannt.
- **EDEP-NET-02:** Stealth-Prüfung berücksichtigt den Richtlinienschlüssel `PrivateProfile`.
- **EDEP-NET-04:** Ausnahme „Authenticated Bypass“ benannt und geprüft.
- **EDEP-TEL-01/-02:** Editionsgrenzen, Microsoft-Empfehlung und Dienst-SID-Typ belegt bzw. geprüft.

### Geändert

- Bezug zur E.L.L.A. Directive auf „inspiriert von“ reduziert; EDEP ist eigenständig.

## [0.0.1] – 2026-09-30

Tag „30.09.2026 21:30 Uhr gestartet“. Erster Entwurf: SPEC 0.1.0, L1-Skripte,
Konformitätskatalog, Richtlinienschema, Designentscheidungen.
