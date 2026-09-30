# Roadmap

Reihenfolge nach Risiko: erst zeigen, dass es Nachfrage gibt, dann bauen.

## M0: Offene Nachweise schließen (vor jeder Veröffentlichung)

Aus [EVIDENCE.md](EVIDENCE.md), alle mit ⏳ markierten Punkte:

- [ ] E-63/E-64: Vollständiger L1-Durchlauf auf frischer VM (Windows 11 Pro **und** Enterprise):
      Install `-Enforce`, `Test-EdepL1` 15/15, Wirkungstests aus VERIFY-YOURSELF 2.2,
      Umgehungstests T-BYP-01/-04/-05/-07, Restore. Protokoll unter `conformance/runs/<datum>-<edition>/`
- [x] E-16: Spaltenposition „Setting Value“ in `auditpol /backup` bestätigt (CI, 2026-09-30)
- [x] E-22: JSON-Feldname `IsSystemPolicy` in `CiTool -lp -json` bestätigt (CI, 2026-09-30)
- [ ] E-34: Herstellerbeleg (Policy CSP) für `PublishUserActivities`/`UploadUserActivities` verlinken
- [ ] E-65: L2-Agent: Rust-Toolchain installieren, `cargo test`
- [ ] GitHub: Private Vulnerability Reporting aktivieren (für SECURITY.md)

## M1: Kostenloses Audit-Tool (dieses Repo, MIT)

- [x] `Invoke-EdepAudit`: Punktzahl, Erklärungen, HTML-Bericht, läuft ohne Adminrechte
- [x] PowerShell-Modul `EDEP` mit Manifest, Build-Skript
- [x] CI: Syntax, BOM, PSScriptAnalyzer, Rauchtests, Schema-Validierung
- [ ] Code-Signing-Zertifikat beschaffen (OV genügt für Skripte; Schlüssel auf Hardware-Token/HSM)
- [ ] Signiert in der PowerShell Gallery veröffentlichen: `Install-Module EDEP`
- [ ] Englische Texte (Katalog und README), Sprache nach `$PSUICulture`
- [ ] Beispielbericht als Bild im README
- [ ] Ankündigung (z. B. r/sysadmin, heise-Forum, LinkedIn, MSP-Communities)

**Erfolgskriterium:** Downloads, Issues, Anfragen. Ohne Resonanz nach 6–8 Wochen: Positionierung überdenken, bevor L2 gebaut wird.

## M2: L1 produktionsreif (dieses Repo, MIT)

- [ ] `Install-EdepL1` auf frischen VMs testen: Windows 11 Home, Pro, Enterprise, Server 2022/2025
- [ ] Aktive Konformitätstests aus `conformance/README.md` (T-NET-03a, T-NET-04a/b, T-TEL-04a, T-OPS-01a) als Skript
- [ ] Store-Apps: Umgang mit AppContainer-Regeln dokumentieren
- [ ] Ausnahmen für `winget` / `Install-Module` im Wartungsfall dokumentieren

## M3: L2-Agent Beta (privates Repo, proprietär)

- [x] Grundgerüst: Richtlinie, Filterplan, SHA-256-Identität, hash-verkettetes Protokoll
- [ ] Authenticode-Prüfung
- [ ] WFP-Umsetzung (Transaktion, Provider, Sublayer, persistent + Boot-Time)
- [ ] Windows-Dienst, Manipulationserkennung, Wartungsmodus
- [ ] Lernmodus: aus Audit-Protokoll einen Richtlinienentwurf erzeugen
- [ ] Installer (MSI/MSIX), signiert
- [ ] Konformität L2 in VM nachgewiesen

## M4: Pilotkunden

- [ ] 5–10 Gespräche mit IT-Dienstleistern (MSPs) vor dem Bau der Konsole
- [ ] 2–3 Pilotinstallationen mit L2 im Audit-, dann Enforce-Modus
- [ ] Supportprozess für Fehlblockaden (Reaktionszeit, Rollback)

## M5: Verwaltungskonsole (proprietär, erst mit zahlenden Piloten)

- [ ] Signierte Richtlinienverteilung (Agent holt ab, mTLS)
- [ ] On-Premises-Variante zuerst, Cloud optional
- [ ] Richtlinien-Generator aus Audit-Protokollen der Flotte
- [ ] Vorfall-Übersicht (nur mit ausdrücklich konfigurierter Log-Weiterleitung, EDEP-LOG-02)
