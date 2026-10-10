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
- [ ] Defender-Signaturupdates unter Enforce lösen: Hostname hinter `146.75.122.172:80` bestimmen (DNS-Client-Protokoll vor dem Versuch an), Race beim ersten Versuch, `MDCoreSvc`/`WdNisSvc` (E-89); Neustart des Defender-Dienstes während der Tests klären
- [ ] Domainfreigabe weiter messen: Suche nach einem Neustart mit leerem Cache, Updateinstallation, fremder Virenschutz, DoH (E-89)
- [ ] Wirkung der Sperrregel für `DiagTrack` (TEL-02) im Audit-Modus messen, `MpDefenderCoreService.exe` in die Defender-Freigabe aufnehmen und prüfen (E-85, E-86)
- [x] `Install-EdepL1` idempotent bei App Control, `Restore-EdepL1` still bei bereits entfernten Richtlinien (Nachtest in Lauf 1)
- [x] Lauf 2 auf Windows 11 Pro 26H2 (Build 26300, korrigierter Stand, nicht committet), 2026-10-03: 15/15 mit TEL-01/TEL-04 WARN, Edge unter Enforce lädt, Updates und BITS auch dort blockiert, Neustart-Vorfall erneut einmal. Protokoll unter `conformance/runs/`
- [x] Lauf 3 (Enterprise 25H2, veröffentlichter Tag `0.1.0-draft.2`, 2026-10-03): Audit 14/15, Enforce 15/15, Restore und sauberer Neustart herstellen den Ausgangszustand; Updates mit `-AllowWindowsUpdate` nicht zuverlässig (erster Block 0 von 9, später Suche ab Versuch 2); Edge-Antwort blieb aus. Protokoll unter `conformance/runs/2026-10-03-Enterprise25H2-26200.9550-HyperV-Lauf3/`
- [x] Entscheidung 2026-10-03: Die Suche nach einer Umgehung der Update-Sperre ist beendet; Enforce wird nur mit definiertem Update-Weg empfohlen (DD-13)
- [x] Entwurf der Zuordnung zu BSI-Grundschutz (Edition 2023: SYS.2.2.3, SYS.2.1, OPS.1.1.3, OPS.1.1.5) nach dem Originaltext, mit Hashes der gelesenen PDFs: [BSI-MAPPING.md](BSI-MAPPING.md)
- [x] E-86 gemessen (Enterprise 25H2): Die Dienstregel gegen `DiagTrack` blockiert nicht; TEL-02 meldet WARN ([Messprotokoll](../conformance/runs/2026-10-03-Enterprise25H2-26200.9550-HyperV-E86/run.md))
- [x] E-86 auf Pro nachgemessen ([Messprotokoll](../conformance/runs/2026-10-04-Pro26H2-26300.9457-HyperV-E86/run.md)): Dienstregel blockiert auch dort nicht; Telemetrie-Level senkt die Verbindungen nicht erkennbar; `dmwappushservice` war gestoppt
- [ ] E-86 weiter: eine Programmregel oder das Abschalten des Dienstes als Ersatz prüfen
- [x] Kompendium-Edition vor der Veröffentlichung erneut geprüft: am 2026-10-10 listet das BSI weiter nur die Edition 2023 ([BSI-MAPPING.md](BSI-MAPPING.md)); vor jedem Release zu wiederholen
- [x] `Test-EdepConformance.ps1` Stufen „nur lesen“ und „Probe“ (lokal und als ZIP-Stand erprobt, Einheitentests, CI-Rauchtest)
- [x] `Test-EdepConformance.ps1` Stufe „Destructive“ geschrieben (Schutz gegen Fehlbedienung, Einheitentests für die Auswertung)
- [x] Stufe „Destructive“ in der Enterprise-VM gelaufen: 13 von 13 Schritten, Rücknahme identisch ([Protokoll](../conformance/runs/2026-10-04-Enterprise25H2-26200.9550-HyperV-Destructive/run.md))
- [x] Stufe „Destructive“ in der Pro-VM gelaufen: 12 von 13 Schritten, `D-E1` (Rücknahme identisch) schlug fehl, weil `Restore-EdepL1` die älteste Sicherung nahm ([Protokoll](../conformance/runs/2026-10-10-Pro26H2-26300.9457-HyperV-Destructive/run.md), [E-91](EVIDENCE.md))
- [x] Stufe „Destructive“ in der Pro-VM wiederholt (mit E-92, eigene Sicherung): 13 von 13 Schritten, `D-E1` identisch, auch nach Neustart ([Lauf 2](../conformance/runs/2026-10-10-Pro26H2-26300.9457-HyperV-Destructive/run.md))
- [x] Signierte Releases `0.1.0-draft.3` bis `0.1.0-draft.6` (SHA256SUMS, SSH-Signatur, signierter Tag; draft.4 und draft.5 mit bestätigtem Bitcoin-Zeitstempel (Blöcke 969890 und 970810), der von draft.6 steht aus; Anleitung in [SIGNING.md](SIGNING.md)); Authenticode-Signatur der Skripte (SYS.2.2.3.A22) bleibt offen, es fehlt ein anerkanntes Zertifikat
- [ ] Kontakt zum BSI erst nach fachkundiger Durchsicht der Zuordnung ([BSI-MAPPING.md](BSI-MAPPING.md), Entwurf; ein signierter Release liegt vor); eine Unterstützung durch das BSI ist nicht zugesagt
- [x] Neustart-Vorfall (E-76) protokolliert nachgemessen ([Lauf 4](../conformance/runs/2026-10-04-Enterprise25H2-26200.9550-HyperV-Lauf4/run.md)): Telemetriewert nach hartem Neustart reproduziert und mit Flush in `Restore-EdepL1` behoben (6 von 6); die früheren umfassenderen Vorfälle bleiben ungeklärt
- [x] Geänderten `Restore-EdepL1` ohne den Fehlalarm zu SECURITY in einer VM gesehen (Pro, Lauf E-86 vom 2026-10-04); auf Enterprise noch nicht
- [x] Windows 11 Home geprüft (Hyper-V, Build 26300.9457, [Protokoll](../conformance/runs/2026-10-10-Home26H2-26300.9457-HyperV/run.md)); App Control dort nicht prüfbar
- [ ] Wiederholung durch Dritte vorbereitet ([WIEDERHOLUNG.md](WIEDERHOLUNG.md), Issue-Vorlage); es steht aus, **Personen zu finden** und eine Rückmeldung zu erhalten (K3)
- [ ] Windows Server: nicht im Geltungsbereich von 1.0.0, später als eigenes Profil (Entscheidung 2026-10-10)
- [x] Vergleichsmaßstab der Stufe geändert: Die Gesamtzahl erlaubender Firewallregeln zählt nicht mehr, weil sie auf Home von selbst wächst (E-96, E-98); ein Lauf in einer VM
- [x] Neuer Release mit den Korrekturen von Installer und Stufe (E-94, E-97, E-98): `0.1.0-draft.6`
- [x] E-63/E-64: Vollständiger L1-Durchlauf auf frischer VM: Windows 11 Enterprise 25H2 ([Lauf 1](../conformance/runs/2026-10-03-Enterprise25H2-26200.9550-HyperV/run.md)) und Windows 11 Pro 26H2 ([Lauf 2](../conformance/runs/2026-10-03-Pro26H2-26300.9457-HyperV/run.md), Phasen A bis E, Phase F ausgelassen), mit `-Enforce`, `Test-EdepL1`, Wirkungstests und Restore; Einschränkungen in [SPEC 3.6](../SPEC.md)
- [x] E-16: Spaltenposition „Setting Value“ in `auditpol /backup` bestätigt (CI, 2026-09-30)
- [x] E-22: JSON-Feldname `IsSystemPolicy` in `CiTool -lp -json` bestätigt (CI, 2026-09-30)
- [x] E-34: Herstellerbeleg für `PublishUserActivities`/`UploadUserActivities` verlinkt (Q-26, 2026-09-30)
- [ ] E-65: L2-Agent: Rust-Toolchain installieren, `cargo test`
- [x] GitHub: Repo öffentlich, Private Vulnerability Reporting aktiviert (2026-09-30)

## M1: Kostenloses Audit-Tool (dieses Repo, MIT)

- [x] `Invoke-EdepAudit`: Punktzahl, Erklärungen, HTML-Bericht, läuft ohne Adminrechte
- [x] PowerShell-Modul `EDEP` mit Manifest, Build-Skript
- [x] CI: Syntax, BOM, Einheitentests (92), Sperre für fehlerhafte native Argumente, PSScriptAnalyzer, Rauchtests, Schema-Validierung, Prüfung der Seitenzahlen
- [ ] Signiert in der PowerShell Gallery veröffentlichen: `Install-Module EDEP`
- [x] Englische Texte: Audit, Prüfdetails, HTML-Bericht, `README.en.md`; Sprache nach Windows-Anzeigesprache oder `-Language`
- [ ] Englische Texte für `Install-EdepL1`/`Restore-EdepL1` und die Spezifikation
- [x] Beispielbericht als Bild im README (aus der CI, hell/dunkel)

## M2: L1 produktionsreif (dieses Repo, MIT)

- [ ] `Install-EdepL1` auf frischen VMs testen: Windows 11 Home, Pro und Enterprise (gemessen), Server 2022/2025 (nicht im Geltungsbereich von 1.0.0)
- [ ] Aktive Konformitätstests aus `conformance/README.md` als Skript: Die Stufe „Destructive“ deckt T-NET-03a, T-NET-04a/b und T-OPS-01a ab; **offen** sind T-NET-02a, T-TEL-02a, T-TEL-04a, T-BYP-02 und T-BYP-03 (im Protokoll unter `notRun`)
- [ ] Store-Apps: Umgang mit AppContainer-Regeln dokumentieren
- [ ] Ausnahmen für `winget` / `Install-Module` im Wartungsfall dokumentieren

## Version 1.0.0: Kriterien (Entwurf, nicht beschlossen)

Stand 2026-10-10. Bisher ist nicht festgelegt, was 1.0.0 bedeutet; dies ist ein **Vorschlag** zur Bewertung durch den Herausgeber. Gemeint ist die Stufe L1 (dieses Repository), nicht L2 oder L3. **Geltungsbereich: Windows 11 (Client).** Windows Server und Windows 10 gehören nicht zu 1.0.0; ein Serverprofil wäre eine spätere Erweiterung mit eigenem Profil. Eine Version 1.0.0 wäre **kein Konformitätsnachweis** und keine Aussage des BSI.

| Nr. | Kriterium | Stand |
| --- | --- | --- |
| K1 | **Update-Weg:** Für den Weg B („Wartungsfenster“, [SPEC 3.5](../SPEC.md)) ist die **Installation von Updates im Fenster** gemessen (Rücknahme, Updates, erneutes Enforce, Prüfung). Der Weg A (zentraler Update-Server) bleibt **ausdrücklich ungemessen** (Betreiber-Verantwortung, [SPEC 3.5](../SPEC.md)): Seine Messung setzt eine Server-Rolle oder einen Update-Proxy voraus und ist von der Umgebung des Betreibers abhängig. | offen: Installation im Fenster ungemessen ([E-89](EVIDENCE.md)); Weg A steht in der SPEC als ungemessen |
| K2 | **Telemetrie:** `EDEP-TEL-02` hat eine gemessene Wirkung für `DiagTrack` **oder** SPEC und README sagen ausdrücklich, dass die Sperre nur den Dienstpfad betrifft und die Wirkung nicht belegt ist. Ein Ersatz (Programmregel, Dienst abschalten) ist gemessen oder als ungemessen benannt. | teilweise: Aussage ist so eingeschränkt ([E-86](EVIDENCE.md)), Ersatz ungemessen |
| K3 | **Reproduzierbarkeit:** Mindestens **eine** Wiederholung der Läufe durch Personen **außerhalb des Projekts**, mit dem Ausgabeformat von `Test-EdepConformance.ps1`, veröffentlicht. | offen: keine |
| K4 | **Fachliche Durchsicht:** Eine fachkundige Person hat die BSI-Zuordnung ([BSI-MAPPING.md](BSI-MAPPING.md)) gelesen; das Ergebnis ist dokumentiert. | offen |
| K5 | **Keine undokumentierte Abweichung:** Jeder bekannte Fehler steht in SPEC 3.6 oder im Belegregister; keine ⏳-Aussage wird als Tatsache verwendet. | bei jedem Release zu prüfen |
| K6 | **Umfang ehrlich:** SPEC 3.6 nennt die ungemessenen Umgebungen innerhalb des Geltungsbereichs (echte Hardware, andere Sprachen, fremder Virenschutz, DoH) und nennt Windows 10 und Windows Server als nicht im Geltungsbereich. Mindestens Windows 11 Enterprise, Pro und Home sind gemessen. | erfüllt (je eine VM, wenige Läufe) |
| K7 | **Release-Hygiene:** signierter Release mit Prüfsummen und bestätigtem Bitcoin-Zeitstempel, CI grün. | erfüllt für `0.1.0-draft.5`; der Zeitstempel von draft.6 steht aus |

**Nicht Voraussetzung** (Vorschlag): Authenticode-Signatur der Skripte (braucht ein anerkanntes Zertifikat, bleibt als Einschränkung), PowerShell Gallery, englische Spezifikation, Messungen auf echter Hardware (K6 verlangt nur, sie ehrlich zu benennen), L2 und L3. **Ausdrücklich nicht im Geltungsbereich:** Windows Server und Windows 10.

**Entschieden (2026-10-10):** Windows Server gehört nicht in den Geltungsbereich von 1.0.0; für K3 genügt eine Wiederholung durch Dritte. **Entschieden:** Weg A bleibt ausdrücklich ungemessen, K1 verlangt nur die Messung des Weges B. **Offen:** Der Entwurf ist als Ganzes noch nicht beschlossen.

## Weitere Stufen

L2 (Agent) und L3 sind **nicht Teil dieses Repositories**. Die Anforderungen an sie stehen in der
[Spezifikation](../SPEC.md), die Referenzarchitektur in [L2-AGENT-ARCHITECTURE.md](L2-AGENT-ARCHITECTURE.md).
