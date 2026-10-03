# CLAUDE.md — E8 ML1 Toolkit

Project context for future Claude Code sessions. Read this before changing code.

## What this is
A PowerShell toolkit that assesses a **Microsoft 365 Business Premium** tenant against
the **ASD Essential Eight, Maturity Level 1**, and produces an **evidence pack** (not just
a score). Built for the UTS 41012 Challenge Studio (Industry Stream) Milestone B+ by
Sadra Hosseinpooraminabad (26103109), for use at 808 IT Solutions.

The guiding distinction: existing tools answer *"did this pass?"* — this one answers
*"what can you actually show the assessor?"*

> Reconstruction note: this tree was rebuilt from the Milestone B report specification
> because the original v3 source was only available as chat attachments, not on disk.
> Reconcile against the real v3 before treating it as canonical.

## Hard rules (do not break)
1. **Collectors assess only.** Nothing under `src/Collectors/` may modify the tenant.
   Only `labs/` scripts may write to the tenant, and only via explicit invocation.
2. **Assessment is the safe default.** `Invoke-E8Assessment.ps1` never weakens anything.
   Any weaken/remediate path must be a separate script that requires an explicit flag.
3. **Blocked ≠ NonCompliant.** A control unavailable at this licensing tier is
   `Blocked` + `LicensingBlocked`, never `NonCompliant`. (Criterion S4.)
4. **PS 5.1 AND PS 7.** No ternary, no `??`, no `?.`, no 3-arg `Join-Path`
   (use `[IO.Path]::Combine`). Force array context with `@()`. RNG has a
   `RNGCryptoServiceProvider` fallback for .NET Framework.
5. **No secrets to disk or output (T8).** No credential, token or password in any
   artefact. Synthetic passwords are generated in memory and never printed.
6. **Break-glass safety.** Resolve and exclude the emergency access account before any
   policy write; refuse to proceed if it cannot be verified.
7. **Tenant safety.** `Assert-E8Tenant` must pass (configured domain is a verified
   domain of the signed-in tenant) before anything runs.

## Layout
```
config/lab.config.json            tenant-specific values (REPLACE_ME blocks runs)
scripts/Connect-E8Lab.ps1         auth (Delegated | AppOnly) + pre-flight safety checks
scripts/Register-E8ScheduledTask.ps1   unattended scheduling
src/Common/E8Toolkit.psm1         verdict factory, license/SKU ctx, population, register
src/Collectors/Get-E8*.ps1        one per strategy; each returns a New-E8Verdict object
src/Evidence/New-EvidencePack.ps1 JSON -> self-contained HTML (no Graph dependency)
labs/Lab01-MFA/Invoke-Lab01.ps1   the destructive weaken/assess/remediate/re-assess cycle
Invoke-E8Assessment.ps1           safe orchestrator: run all collectors -> JSON + HTML
output/                           timestamped run artefacts (git-ignored)
```

## The verdict contract (New-E8Verdict)
Every collector returns the same shape:
`controlId, strategy, maturityLevel, verdict, verdictReason, automatability,
assessmentMode, coverage{}, evidence{}, attestationQuestions[], tenantDomain, collectedUtc`.
- `verdict` ∈ Compliant | Partial | NonCompliant | Blocked | NotAssessed
- `automatability` ∈ Automated | PartiallyAutomated | AttestationOnly | LicensingBlocked
- `verdictReason` is a plain-English sentence for a non-technical reviewer, never a code.

## Control register (src/Common/E8Toolkit.psm1 → Get-E8ControlRegister)
| # | Strategy | Collector | Baseline automatability |
|---|----------|-----------|------------------------|
| 1 | Multi-factor authentication | Get-E8MfaCoverage | Automated |
| 2 | Restrict administrative privileges | Get-E8RestrictAdminPrivileges | PartiallyAutomated |
| 3 | Patch applications | Get-E8PatchApplications | PartiallyAutomated (LicensingBlocked w/o Intune+Defender) |
| 4 | Patch operating systems | Get-E8PatchOperatingSystems | PartiallyAutomated (LicensingBlocked w/o Intune) |
| 5 | Configure Microsoft Office macro settings | Get-E8OfficeMacros | PartiallyAutomated (LicensingBlocked w/o Intune) |
| 6 | User application hardening | Get-E8UserApplicationHardening | PartiallyAutomated (LicensingBlocked w/o Intune) |
| 7 | Application control | Get-E8ApplicationControl | AttestationOnly |
| 8 | Regular backups | Get-E8Backups | AttestationOnly |

## Running
```powershell
# one-time: edit config/lab.config.json (remove every REPLACE_ME) and install the SDK
Install-Module Microsoft.Graph -Scope CurrentUser

# safe full assessment (interactive)
.\Invoke-E8Assessment.ps1

# unattended (needs app-only cert thumbprint or client-secret env var in config)
.\Invoke-E8Assessment.ps1 -Mode AppOnly -Quiet
```

## Known gaps / next work
- `labs/Lab01-MFA/Invoke-Lab01.ps1` (the weaken/remediate cycle) is not yet in this
  reconstructed tree — port it from v3. It must exclude the break-glass account and
  poll for directory propagation rather than a fixed sleep.
- Collectors 3–6 confirm policy/asset *existence*; value-level and endpoint
  enforcement still need Defender for Business TVM data or attestation.
- Pester suite lives in `tests/` (Pester 5/6, dashed `Should -Be` syntax) with
  known-good/known-bad fixtures. CI (`.github/workflows/tests.yml`) runs it on both
  Windows PowerShell 5.1 and PowerShell 7 on every push/PR.
- `Get-E8LicenseContext` SKU matching is heuristic; verify SkuPartNumbers against the
  real tenant.
```
