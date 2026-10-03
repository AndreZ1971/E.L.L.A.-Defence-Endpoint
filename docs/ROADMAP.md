# Roadmap

Dieses Repository enthält Spezifikation, L1-Baseline und Audit-Tool. Hier steht, was daran noch offen ist.

## M0: Offene Nachweise schließen (vor jeder Veröffentlichung)

Aus [EVIDENCE.md](EVIDENCE.md), alle mit ⏳ markierten Punkte:

- [x] Lauf 0 (Entdeckungslauf, Windows-Sandbox, Enterprise 24H2 26100.9550, 2026-10-02): drei Fehler gefunden und behoben
      (Installer-Argument, NET-10 an der Laufwerkswurzel, NET-03-Wirkung/B-08), Protokoll unter `conformance/runs/`.
      Das ist **kein** vollständiger Durchlauf: App Control, Defender und Windows Update waren dort nicht prüfbar.
- [x] Lauf 1 (Hyper-V-VM, Windows 11 Enterprise 25H2, 2026-10-03): vollständiger Durchlauf Phase A bis F, 15/15 im Enforce-Modus. Befunde: Updates, Defender-Signaturen und BITS unter Enforce nicht erreichbar (Dienstregeln greifen nicht), `Install` nicht idempotent bei App Control, Rücknahme einmal wirkungslos (nicht reproduziert). Protokoll unter `conformance/runs/`
- [x] TEL-04 prüft die Wirkung (`-ProbeUpdates`), in der VM nachgemessen (Nachtest in Lauf 1)
- [x] Ursache der Dienstregeln eingegrenzt: Der Update-Client verbindet mit dem Token des aufrufenden Benutzers ohne Dienst-SID (Mitschnitt, E-84); SYSTEM-initiierte Scans und BITS offen
- [x] Freigabe nach Domainnamen (Programm `svchost.exe` + Dynamic Keywords) in der VM gemessen: Suche und BITS zu Microsoft gelingen, `example.org` bleibt gesperrt (E-88); setzt Netzwerkschutz voraus
- [x] Domainfreigabe als Option `-AllowWindowsUpdate` umgesetzt und in der VM nachgemessen (Audit-Modus, Idempotenz, Rücknahme; E-88, E-90)
- [ ] Domainfreigabe weiter messen: nach Neustart, mit Updateinstallation, Defender-Signaturen (`WdNisSvc`, `MDCoreSvc`), fremder Virenschutz, DoH (E-89)
- [ ] Wirkung der Sperrregel für `DiagTrack` (TEL-02) im Audit-Modus messen, `MpDefenderCoreService.exe` in die Defender-Freigabe aufnehmen und prüfen (E-85, E-86)
- [x] `Install-EdepL1` idempotent bei App Control, `Restore-EdepL1` still bei bereits entfernten Richtlinien (Nachtest in Lauf 1)
- [x] Lauf 2 auf Windows 11 Pro 26H2 (Build 26300, korrigierter Stand, nicht committet), 2026-10-03: 15/15 mit TEL-01/TEL-04 WARN, Edge unter Enforce lädt, Updates und BITS auch dort blockiert, Neustart-Vorfall erneut einmal. Protokoll unter `conformance/runs/`
- [ ] Neustart-Vorfall (E-76) mit sauber protokolliertem Ablauf (Uhrzeiten, Art des Neustarts, Eingriffe vorher) klären
- [ ] Windows 11 Home und Windows Server prüfen
- [ ] E-63/E-64: Vollständiger L1-Durchlauf auf frischer VM (Windows 11 Pro **und** Enterprise); Lauf 1 in Hyper-V mit Evaluierungs-ISO in Vorbereitung:
      Install `-Enforce`, `Test-EdepL1` 15/15, Wirkungstests aus VERIFY-YOURSELF 2.2,
      Umgehungstests T-BYP-01/-04/-05/-07, Restore. Protokoll unter `conformance/runs/<datum>-<edition>/`
- [x] E-16: Spaltenposition „Setting Value“ in `auditpol /backup` bestätigt (CI, 2026-09-30)
- [x] E-22: JSON-Feldname `IsSystemPolicy` in `CiTool -lp -json` bestätigt (CI, 2026-09-30)
- [x] E-34: Herstellerbeleg für `PublishUserActivities`/`UploadUserActivities` verlinkt (Q-26, 2026-09-30)
- [ ] E-65: L2-Agent: Rust-Toolchain installieren, `cargo test`
- [x] GitHub: Repo öffentlich, Private Vulnerability Reporting aktiviert (2026-09-30)

## M1: Kostenloses Audit-Tool (dieses Repo, MIT)

- [x] `Invoke-EdepAudit`: Punktzahl, Erklärungen, HTML-Bericht, läuft ohne Adminrechte
- [x] PowerShell-Modul `EDEP` mit Manifest, Build-Skript
- [x] CI: Syntax, BOM, Einheitentests (23), Sperre für fehlerhafte native Argumente, PSScriptAnalyzer, Rauchtests, Schema-Validierung, Prüfung der Seitenzahlen
- [ ] Signiert in der PowerShell Gallery veröffentlichen: `Install-Module EDEP`
- [x] Englische Texte: Audit, Prüfdetails, HTML-Bericht, `README.en.md`; Sprache nach Windows-Anzeigesprache oder `-Language`
- [ ] Englische Texte für `Install-EdepL1`/`Restore-EdepL1` und die Spezifikation
- [x] Beispielbericht als Bild im README (aus der CI, hell/dunkel)

## M2: L1 produktionsreif (dieses Repo, MIT)

- [ ] `Install-EdepL1` auf frischen VMs testen: Windows 11 Home, Pro, Enterprise, Server 2022/2025
- [ ] Aktive Konformitätstests aus `conformance/README.md` (T-NET-03a, T-NET-04a/b, T-TEL-04a, T-OPS-01a) als Skript
- [ ] Store-Apps: Umgang mit AppContainer-Regeln dokumentieren
- [ ] Ausnahmen für `winget` / `Install-Module` im Wartungsfall dokumentieren

## Weitere Stufen

L2 (Agent) und L3 sind **nicht Teil dieses Repositories**. Die Anforderungen an sie stehen in der
[Spezifikation](../SPEC.md), die Referenzarchitektur in [L2-AGENT-ARCHITECTURE.md](L2-AGENT-ARCHITECTURE.md).
