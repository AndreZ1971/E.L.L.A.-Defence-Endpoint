# E.D. Endpoint Profile (EDEP)

[![CI](https://github.com/AndreZ1971/E.L.L.A.-Defence-Endpoint/actions/workflows/ci.yml/badge.svg)](https://github.com/AndreZ1971/E.L.L.A.-Defence-Endpoint/actions/workflows/ci.yml) [![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE) [![Specification](https://img.shields.io/badge/SPEC-0.1.0_draft-orange.svg)](SPEC.md)

**[Deutsch](README.md) · English**

**Open security profile for Windows endpoints: outbound zero trust, telemetry sovereignty and deterministic isolation.**

EDEP defines what a Windows computer must technically enforce so that:

- No program talks to the network unless it is explicitly allowed to.
- The operating system sends only unavoidable telemetry, and the user can see it.
- Every block is logged locally.
- On detected data exfiltration the host isolates itself, deterministically, not on a model's suspicion.

EDEP is **not an antivirus**. It is designed to complement Microsoft Defender or another AV product.

> **Status:** draft 0.1.0. The specification is not yet sealed. The normative specification
> and the detailed documentation are currently written in German; the audit tool and this
> page are available in English.

## Free audit: how open is your Windows?

By default Windows lets every program send traffic outbound, even with Defender.
The audit shows in about a minute what applies to your computer. It **changes nothing**
and also runs without admin rights.

```powershell
# In the folder baseline\L1 (run as administrator for the complete result)
.\Invoke-EdepAudit.ps1 -Open
```

Result: a score from 0 to 100, categories (outbound and inbound traffic, program control,
telemetry, logging, attack surface) and, for every open item, an explanation with a concrete
recommendation, on the console and as an HTML report. The language follows the Windows display
language; `-Language en` or `-Language de` forces it.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/images/audit-example-dark.png">
  <img alt="EDEP audit report: score out of 100, categories with progress bars and findings with reasoning and recommendation" src="docs/images/audit-example-light.png" width="720">
</picture>

<sub>Example report of an unhardened Windows Server 2025 (GitHub Actions runner, with admin rights), generated in CI.</sub>

## Don't believe it, verify it

| Question                                         | Answer                                                                                                                                           |
| ------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| Is what's written here true?                     | Every technical claim has a source or a measurement: [evidence register](docs/EVIDENCE.md). Anything not yet verified is openly marked ⏳ there. |
| Where do the facts come from?                    | 26 linked sources, mostly Microsoft Learn and MITRE ATT&CK: [SPEC, Annex B](SPEC.md#anhang-b--quellen)                                           |
| What can EDEP **not** do?                        | Residual risks and seven known bypasses, each with a test: [SPEC 3.3/3.4](SPEC.md#34-bekannte-umgehungen-normativ)                               |
| Where does EDEP deviate from Microsoft, and why? | [DD-12](docs/DESIGN-DECISIONS.md)                                                                                                                |
| How do I check it myself?                        | In 5 minutes without risk, in 30 minutes in a VM: [verify yourself](docs/VERIFY-YOURSELF.md)                                                     |
| Which mistakes were already found?               | [Errata](docs/EVIDENCE.md#errata)                                                                                                                |
| I found a hole.                                  | [SECURITY.md](SECURITY.md)                                                                                                                       |

## Levels

| Level           | Implementation                                                                     | Own code                     |
| --------------- | ---------------------------------------------------------------------------------- | ---------------------------- |
| **L1 Baseline** | Windows built-ins only (firewall, App Control, policies)                           | no, [scripts](baseline/L1/)  |
| **L2 Enforced** | Agent with WFP filters, program identity by signature/hash, boot-time filters      | yes, without a kernel driver |
| **L3 Isolated** | Deterministic emergency isolation, metadata anomaly detection, model advisory only | yes                          |

## Quick start L1

In **PowerShell as administrator** in the folder `baseline\L1`:

```powershell
# 1. Only show what would happen
.\Install-EdepL1.ps1 -DeployAppControlAudit -WhatIf

# 2. Apply in audit mode (outbound still allowed, everything is logged)
.\Install-EdepL1.ps1 -DeployAppControlAudit

# 3. Check
.\Test-EdepL1.ps1

# 4. After reviewing the firewall log: block outbound by default
.\Install-EdepL1.ps1 -Enforce -DeployAppControlAudit `
    -AllowProgram "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe"

# Undo (restores the state before the first application)
.\Restore-EdepL1.ps1
```

**Caution with `-Enforce`:** afterwards only programs with an allow rule have network access:
Windows core networking, update services, Defender and the programs listed under `-AllowProgram`.
Store apps keep their own Windows rules. PowerShell, `curl.exe`, `certutil` and the other
Annex A tools are blocked outbound, including for `Install-Module` and `winget` scripts.
`-AllowProgram` refuses paths that non-admins can modify (EDEP-NET-10).

Install and restore messages are currently German only.

## Contents

| Path                                                             | Contents                                                             |
| ---------------------------------------------------------------- | -------------------------------------------------------------------- |
| [SPEC.md](SPEC.md)                                               | Normative specification: threat model, requirements, levels (German) |
| [conformance/](conformance/README.md)                            | Conformance tests per requirement                                    |
| [baseline/L1/](baseline/L1/)                                     | Audit plus apply, check and restore for L1 (module `EDEP`)           |
| [tools/](tools/)                                                 | Build and sign the module, validate policies                         |
| [schema/edep-policy.schema.json](schema/edep-policy.schema.json) | Policy language (JSON Schema)                                        |
| [docs/EVIDENCE.md](docs/EVIDENCE.md)                             | Evidence register                                                    |
| [docs/DESIGN-DECISIONS.md](docs/DESIGN-DECISIONS.md)             | Why EDEP is built this way                                           |
| [docs/ROADMAP.md](docs/ROADMAP.md)                               | Milestones                                                           |

## What EDEP does not do

Attackers with administrator or kernel rights, the content of encrypted connections, abuse of
allowed programs and compromised signed software are out of scope. Details:
[SPEC.md, section 3.3](SPEC.md#33-ausdrücklich-nicht-im-geltungsbereich-restrisiken).
These limits are part of the standard and must not be omitted from any product description.

## License

[MIT](LICENSE)
