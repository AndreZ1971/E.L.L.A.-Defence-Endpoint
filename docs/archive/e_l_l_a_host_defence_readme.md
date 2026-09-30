Verstanden. Automotive wird komplett gestrichen. **E.D. Endpoint (E.L.L.A. Host Defence)** wird strikt als vollständig eigenständiges Windows-Sicherheitsprodukt behandelt.

Hier ist die bereinigte, fokussierte `README.md`, die sich ausschließlich auf den Windows-Hostschutz konzentriert:

---

# E.D. Endpoint (E.L.L.A. Host Defence)

Deterministische Host-Abschirmung, Kernel-Socket-Filterung und lokale Inferenz-Firewall für Windows-Systeme (x86 / ARM64).

E.D. Endpoint erzwingt Netzwerk- und Speichersouveränität direkt im Betriebssystem. Das System arbeitet vollständig autark auf dem Host: ohne Cloud-Telemetrie, ohne Signatur-Server und ohne Abonnement-Zwang.

---

## 1. Systemarchitektur

E.D. Endpoint agiert über drei strikt getrennte Kontrollebenen auf dem Host-Rechner:

```text
       [ Windows Shell / Explorer / UI-Ebene ]
                          │
       ┌──────────────────▼──────────────────┐
       │ In-Memory Hooks (Windhawk Engine)   │  <- Visual & Execution Level:
       │ - Blockiert UI-Ads, Werbekacheln   │     Liquidiert unerwünschte Frames
       │ - Verhindert In-Process-Injections  │     direkt im Prozess-Speicher
       └──────────────────┬──────────────────┘
                          │
       [ Anwendungs- & Prozess-Ebene (Whitelist) ]
                          │
       ┌──────────────────▼──────────────────┐
       │ E.L.L.A. Directive Host Agent       │  <- Process Boundary:
       │ - Zero-Trust App-Whitelist          │     Nur autorisierte Binaries
       │ - Blockiert Schattenprozesse/DLLs   │     dürfen Sockets öffnen
       └──────────────────┬──────────────────┘
                          │
       ┌──────────────────▼──────────────────┐
       │ WFP Kernel-Filter (WFP Callout)     │  <- Live-Pfad (Ebene 1):
       │ - O(1) BLAKE3 Port- & IP-Validierung│     Default-Drop für unsignierte
       │ - Stealth-Drop / Tarpit für Scans   │     Verbindungen (< 5 µs)
       └──────────────────┬──────────────────┘
                          │
       ┌──────────────────▼──────────────────┐
       │ Lokales SLM (Asynchroner Wächter)   │  <- Semantischer Pfad (Ebene 2):
       │ - Überwacht Payload-Muster          │     Analysiert Datenströme auf
       │ - Steuert physische WLAN-Adapter    │     Exfiltration & steuert Air-Gap
       └──────────────────┬──────────────────┘
                          │
             [ Physischer Netzwerkadapter ]

```

---

## 2. Kernkomponenten

### In-Memory-Entkernung (Windhawk Engine)

* **Adressraum-Eingriff:** Modifiziert Systemprozesse (`explorer.exe`, `StartMenuExperienceHost.exe`) direkt im RAM.


* **Native API-Interzeption:** Fängt grafische API-Aufrufe ab, bevor Render-Pipelines greifen. Beseitigt Windows-Telemetriebanner, erzwungene Web-Suchen und OS-Werbung auf Pixelebene.


* **Injection-Schutz:** Verhindert das Einschleusen nicht-autorisierter DLLs und Payloads in kritische System-Threads.



### WFP Kernel Callout-Treiber

* **Kernel-Netzwerkstack:** Nativ in die *Windows Filtering Platform* (WFP) integriert.


* **Pre-Infection-Abwehr:** Eingehende Portscans verpuffen via **Silent Drop** (Host reagiert wie ein schwarzes Loch) oder werden in **Tarpits** gebunden, um Scan-Tools festzusetzen.


* **Deterministische Socket-Kopplung:** Jeder Port und Socket ist an eine Zero-Trust-Prozess-Whitelist gekoppelt. Nicht autorisierte Binaries oder Skripte werden in $< 5\ \mu\text{s}$ geblockt.



### Lokales SLM & Hardware-Killswitch

* **Asynchroner Payload-Wächter:** Ein quantisiertes Small Language Model (0.5B bis 1.5B INT4) analysiert ausgehende Payload-Strukturen auf Exfiltrationsmuster.


* **Physischer Air-Gap:** Erkennt das Modell kritische Datenabflüsse oder bösartige Anomalien, trennt es Netzwerk- und WLAN-Adapter hardwarenah per Treiberbefehl ab.



---

## 3. Vergleich: E.D. Endpoint vs. Klassische AV-Suiten

| Merkmal | Kommerzielle Suiten (Defender, Norton etc.) | E.D. Endpoint |
| --- | --- | --- |
| **OS-Telemetrie** | Ignoriert oder schützt Microsoft-eigene Dienste

 | Blockiert Diagnosedienste (`DiagTrack`) und System-Werbung vollständig

 |
| **Cloud-Abhängigkeit** | Zwingender Cloud-Sync, Telemetrie-Uploads, Abos

 | 100 % autark, Offline-First, keine externen Server-Aufrufe

 |
| **Netzwerkschutz** | Reagiert meist post-breach nach Dateispeicherung

 | Pre-Infection-Stop auf Kernel-Ebene, Adapter-Killswitch

 |
| **Systemlast** | Schwerfällige UI-Prozesse, Hintergrundscanner

 | Minimalistischer Host-Agent, deterministische O(1)-Prüfung

 |

---

## 4. Risikomanagement & Ausfallsicherheit

| Risiko | Ursache | Gegenmaßnahme |
| --- | --- | --- |
| **Windows-Updates / PatchGuard**<br> | Geänderte Kernel-Strukturen und Offset-Verschiebungen nach Patches können Memory-Hooks destabilisieren.

 | **Modularer Failsafe:** Schlägt ein Hook fehl, deaktiviert er sich isoliert, ohne Systemabstürze (BSOD) auszulösen.

 |
| **False Positives**<br> | Restriktive Socket-Sperren oder Killswitches behindern lokale Compiler oder Entwickler-Tools.

 | **Hardwarenaher Bypass-Modus:** Passwortgeschützter Wartungsmodus schaltet den WFP-Filter temporär auf transparenten Durchzug.

 |
| **Ressourcenkonflikte**<br> | SLM beansprucht RAM/VRAM bei parallelen rechenintensiven Aufgaben (Rendering, lokale Builds).

 | **Quantisierte Micro-Modelle:** Nutzung von 0.5B–1.5B INT4 mit Zuweisung auf Hintergrundkerne oder statische Heuristiken bei Volllast.

 |

---

## 5. Lizenz

Dieses Projekt steht unter den Bedingungen der **MIT-Lizenz**.

---

Soll als nächster Schritt die Konfigurationsstruktur (z. B. `whitelist.json` / `config.yaml` für Prozess-Hashes und den Bypass-Modus) oder der Aufbau des WFP-Callout-Treibers ausgearbeitet werden?