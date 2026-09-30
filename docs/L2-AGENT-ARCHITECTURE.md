# L2-Agent — Referenzarchitektur (Entwurf)

Nicht normativ. Beschreibt, wie eine L2-Implementierung aufgebaut sein kann, ohne eigenen
Kernel-Treiber (DD-01).

```text
 ┌────────────────────────────────────────────────────────────┐
 │  edep-ui.exe  (Benutzerkontext, optional)                  │
 │  - zeigt Protokoll, Hinweise, Wartungsmodus-Anfrage        │
 └───────────────▲────────────────────────────────────────────┘
                 │ Named Pipe, ACL: Administratoren + interaktiver Nutzer (nur lesen)
 ┌───────────────┴────────────────────────────────────────────┐
 │  edep-agent  (Windows-Dienst, LocalSystem)                 │
 │                                                            │
 │  PolicyLoader ── validiert gegen JSON-Schema (POL-01..03)  │
 │       │                                                    │
 │  IdentityResolver ── Authenticode / SHA-256 (ID-03, ID-04) │
 │       │   WinVerifyTrust, CryptCATAdmin*, Hash-Cache       │
 │       │   nach (Pfad, Dateigröße, Änderungszeit, FileId)   │
 │       │                                                    │
 │  FilterCompiler ── Richtlinie → WFP-Filter                 │
 │       │   eigener Provider + Sublayer (NET-07)             │
 │       │   Default-Block: PERSISTENT | BOOTTIME (NET-08)    │
 │       │   Erlaubnis: ALE_AUTH_CONNECT_V4/V6 mit            │
 │       │   ALE_APP_ID bzw. Dienst-SID (ID-05)               │
 │       │                                                    │
 │  TamperWatch ── FwpmFilterSubscribeChanges0 + 60-s-Abgleich │
 │       │   (LOG-03)                                         │
 │  AuditLog ── JSON Lines, SHA-256-Kette (LOG-04, LOG-05)    │
 │  Maintenance ── zeitbegrenzt, lokal bestätigt (OPS-03)     │
 └───────────────┬────────────────────────────────────────────┘
                 │ FwpmEngineOpen0 / FwpmTransactionBegin0 / FwpmFilterAdd0
 ┌───────────────▼────────────────────────────────────────────┐
 │  Windows Filtering Platform (Base Filtering Engine)        │
 └────────────────────────────────────────────────────────────┘
```

## Kernpunkte

- **Transaktional:** Jede Richtlinienänderung wird in einer WFP-Transaktion angewendet
  (`FwpmTransactionBegin0` … `Commit0`). Schlägt ein Filter fehl, wird alles
  zurückgerollt, und die alte Richtlinie bleibt aktiv (POL-03).
- **Identität zur Programmidentität:** WFP kennt nur den Pfad (`ALE_APP_ID`). Der Agent
  gibt einen Pfad erst frei, nachdem er dessen Signatur bzw. Hash geprüft hat. Eine
  Änderung der Datei (Überwachung über `ReadDirectoryChangesW` und USN-Journal) entzieht
  die Freigabe sofort, bis die Prüfung erneut bestanden ist (ID-04).
  _Restrisiko:_ Zwischen Prüfung und Ausführung kann eine Datei getauscht werden
  (TOCTOU). Das schließt App Control im erzwingenden Modus (ID-02). Deshalb ist ID-02
  auf L2 Pflicht.
- **Gewichte:** Sublayer-Gewicht über den Standard-Sublayern der Windows-Firewall. Die
  Blockfilter des Agenten sind damit nicht durch Firewall-Erlaubnisregeln aufhebbar.
- **Fail-closed:** Die Default-Block-Filter sind persistent. Stirbt der Dienst, gilt
  weiterhin „alles blockiert außer freigegeben“ (OPS-04).
- **Sprache:** Rust (`windows`-Crate) oder C++. Keine Laufzeit mit eigener
  Netzwerkkomponente im Dienstprozess.
- **Kein Netzwerkzugriff des Agenten selbst.** Der Agent hat keine Erlaubnisregel.
  Updates erfolgen über den Paketmanager bzw. Windows Update.

## Offene Punkte

- Store-Apps (AppContainer): Freigabe über Paket-SID (`ALE_PACKAGE_ID`) in die
  Richtliniensprache aufnehmen.
- DNS-Protokollierung (NET-06): ETW-Anbieter `Microsoft-Windows-DNS-Client` gegenüber dem
  Betriebsprotokoll bewerten.
- Signierung und Verteilung des Dienstes (Authenticode, MSIX oder MSI).
