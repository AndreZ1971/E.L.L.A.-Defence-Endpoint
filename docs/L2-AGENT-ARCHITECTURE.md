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
 │       │   Default-Block: je 1x BOOTTIME + 1x PERSISTENT    │
 │       │   (getrennte Filter, nie kombiniert; NET-08)       │
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
- **Gewichte und Arbitrierung** ([Filter Arbitration](https://learn.microsoft.com/en-us/windows/win32/fwp/filter-arbitration)):
  WFP wertet alle Sublayer aus. Ein normaler Block-Filter ist ein _hard block_ und kann
  in keinem anderen Sublayer aufgehoben werden. Ein _hard permit_ in einem **höher**
  priorisierten Sublayer setzt sich aber durch. Deshalb bekommt der EDEP-Sublayer das
  höchste Gewicht (0xFFFF), und TamperWatch meldet jeden fremden Sublayer mit gleichem
  oder höherem Gewicht (NET-07, Umgehung B-06).
- **Boot-Time und persistent getrennt:** `FWPM_FILTER_FLAG_BOOTTIME` und
  `FWPM_FILTER_FLAG_PERSISTENT` sind laut [FWPM_FILTER0](https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_filter0)
  nicht kombinierbar. Der Plan enthält je Ebene einen Boot-Time- und einen persistenten
  Filter; der Übergang beim BFE-Start ist atomar ([WFP Operation](https://learn.microsoft.com/en-us/windows/win32/fwp/basic-operation)).
- **Provider an Dienst gebunden:** Der Provider trägt den Dienstnamen des Agenten, der
  Dienst hat den Starttyp _Automatisch_. Andernfalls deaktiviert die BFE die Filter des
  Providers beim Start (FWPM_FILTER0, Flag `FWPM_FILTER_FLAG_DISABLED`).
- **Fail-closed:** Die Default-Block-Filter sind persistent. Stirbt der Dienst, gilt
  weiterhin „alles blockiert außer freigegeben“ (OPS-04).
- **Alternative ohne eigenen Agenten prüfen:** Windows-Firewall-Regeln können an
  App-Control-AppID-Tags gebunden werden (`New-NetFirewallRule -PolicyAppId`). Das wäre
  Programmidentität mit Bordmitteln (DD-11). Vor dem Bau von `wfp::apply` evaluieren.
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
