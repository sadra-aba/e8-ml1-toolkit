# E8 ML1 Toolkit

[![tests](https://github.com/sadra-aba/e8-ml1-toolkit/actions/workflows/tests.yml/badge.svg)](https://github.com/sadra-aba/e8-ml1-toolkit/actions/workflows/tests.yml)

Automated **Essential Eight Maturity Level 1** assessment and **evidence pack**
generator for **Microsoft 365 Business Premium** tenants.

Existing tools answer *"did this pass?"* This one answers a different question:
**"what can you actually show the assessor?"** — it produces a dated, attributable
evidence pack an insurer or procurement reviewer will accept, not just a score.

> UTS 41012 Challenge Studio (Industry Stream) — Sadra Hosseinpooraminabad (26103109).
> Built for use at 808 IT Solutions. Assesses an isolated lab tenant with synthetic data.

## Highlights
- **Evidence pack, not a score** — self-contained HTML (and machine-readable JSON),
  timestamped in UTC and Sydney time, with per-control reasoning in plain English.
- **Honest classification** — every control is labelled `Automated`,
  `PartiallyAutomated`, `AttestationOnly` or `LicensingBlocked`. A control that is
  unavailable at this licensing tier is reported **Blocked**, never conflated with a
  failed (`NonCompliant`) control.
- **Weaken → assess → remediate → re-assess** — the same collector runs before and
  after remediation, so any change in verdict is attributable to the configuration
  change, not the measurement.
- **Safe by default** — the orchestrator only reads. The destructive weaken cycle is
  a separate, guarded script. Break-glass account is always resolved and excluded.
- **Runs on Windows PowerShell 5.1 and PowerShell 7.**

## Quick start
```powershell
Install-Module Microsoft.Graph -Scope CurrentUser   # one-time
# edit config/lab.config.json (remove every REPLACE_ME)
.\Invoke-E8Assessment.ps1                            # safe full assessment -> output/
.\labs\Lab01-MFA\Invoke-Lab01.ps1 -ConfirmWeaken     # MFA before/after evidence
Install-Module Pester -MinimumVersion 5.5 -Scope CurrentUser -SkipPublisherCheck
Invoke-Pester -Path .\tests\E8Toolkit.Tests.ps1      # 22 unit tests (Pester 5+)
```
Full instructions: [docs/QUICKSTART-LIVE-RUN.md](docs/QUICKSTART-LIVE-RUN.md).
Project conventions and hard rules: [CLAUDE.md](CLAUDE.md).

## The eight controls
| # | Strategy | Collector | Automatability |
|---|----------|-----------|----------------|
| 1 | Multi-factor authentication | `Get-E8MfaCoverage` | Automated |
| 2 | Restrict administrative privileges | `Get-E8RestrictAdminPrivileges` | PartiallyAutomated |
| 3 | Patch applications | `Get-E8PatchApplications` | PartiallyAutomated / LicensingBlocked |
| 4 | Patch operating systems | `Get-E8PatchOperatingSystems` | PartiallyAutomated / LicensingBlocked |
| 5 | Configure Microsoft Office macro settings | `Get-E8OfficeMacros` | PartiallyAutomated / LicensingBlocked |
| 6 | User application hardening | `Get-E8UserApplicationHardening` | PartiallyAutomated / LicensingBlocked |
| 7 | Application control | `Get-E8ApplicationControl` | AttestationOnly |
| 8 | Regular backups | `Get-E8Backups` | AttestationOnly |

## Layout
```
config/                tenant-specific values (template; REPLACE_ME blocks runs)
scripts/               auth, seeding, teardown, scheduling
src/Common/            verdict contract, licensing detection, helpers, register
src/Collectors/        one assessor per strategy (read-only)
src/Evidence/          JSON -> self-contained HTML
labs/Lab01-MFA/        weaken/assess/remediate/re-assess cycle
tests/                 Pester suite + known-good/bad fixtures
Invoke-E8Assessment.ps1   safe orchestrator (assessment only)
```

## Scope & disclaimer
Maturity Level 1 only; Microsoft 365 Business Premium only; point-in-time; assesses
configuration state, not control effectiveness. This toolkit **supports** an
assessment — it does not constitute a formal or IRAP-equivalent assessment. No
credentials or secrets are ever written to disk or into any artefact.

## References
- ASD — [Essential Eight Maturity Model](https://www.cyber.gov.au/business-government/asds-cyber-security-frameworks/essential-eight/essential-eight-maturity-model)
- CISA — [ScubaGear](https://github.com/cisagov/ScubaGear) · [Maester](https://maester.dev)
