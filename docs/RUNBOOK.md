# RUNBOOK — E8 ML1 Toolkit

## Prerequisites
- Windows PowerShell 5.1 **or** PowerShell 7.
- Microsoft Graph PowerShell SDK: `Install-Module Microsoft.Graph -Scope CurrentUser`.
- A Microsoft 365 **Business Premium** tenant (Standard/Basic cannot support most
  controls — they lack Conditional Access, Intune and Defender for Business).
- Global Administrator (or equivalent) for the assessing/consenting account.
- **Security Defaults disabled** (mutually exclusive with Conditional Access).

## Configure
Edit `config/lab.config.json` and remove **every** `REPLACE_ME`:
- `tenant.primaryDomain`, `tenant.tenantId`
- `breakGlass.userPrincipalName` — the emergency access account, excluded from MFA
  enforcement and from the assessable population.
- For unattended runs, `auth.appOnly.clientId` and either a
  `certificateThumbprint` (preferred) or the client secret in the env var named by
  `clientSecretEnvVar`.

The toolkit refuses to run while any `REPLACE_ME` remains.

## Delegated Graph scopes (least privilege)
`User.ReadWrite.All, Group.ReadWrite.All, Directory.Read.All, Policy.Read.All,
Policy.ReadWrite.ConditionalAccess, Application.Read.All, RoleManagement.Read.Directory,
Organization.Read.All, DeviceManagementConfiguration.Read.All,
DeviceManagementManagedDevices.Read.All`

A read-only client can grant `Get-E8ReadOnlyScopeList` (drops the `*ReadWrite` scopes):
assessment works, remediation is withheld.

## Run a safe assessment
```powershell
cd C:\E8-Toolkit
.\Invoke-E8Assessment.ps1              # interactive (delegated)
.\Invoke-E8Assessment.ps1 -Mode AppOnly -Quiet   # unattended
```
Outputs land in `output/`:
- `assessment-<stamp>.json` — machine-readable results (all eight controls).
- `evidence-pack-<stamp>.html` — self-contained, printable reviewer-facing pack.

Regenerate a pack from stored JSON without re-assessing:
```powershell
. .\src\Evidence\New-EvidencePack.ps1 -RunJsonPath .\output\assessment-<stamp>.json `
    -OutputPath .\output\evidence-pack-regenerated.html
```

## Schedule unattended runs
```powershell
.\scripts\Register-E8ScheduledTask.ps1 -Frequency Weekly -DayOfWeek Monday -Time 02:00
```

## Verdict / automatability meanings
- **Compliant / Partial / NonCompliant** — assessed and graded.
- **Blocked** (`LicensingBlocked`) — cannot be assessed/configured at this licensing
  tier. A purchasing decision, not a configuration failure. Never counted as a fail.
- **NotAssessed** (`AttestationOnly`) — not determinable from tenant config; the pack
  lists the attestation questions a human must answer.

## Safety
- `Assert-E8Tenant` aborts unless the configured domain is verified on the signed-in
  tenant.
- The destructive weaken/remediate cycle is **not** in `Invoke-E8Assessment.ps1`; it is
  a separate `labs/` script and must be run deliberately.
- No secrets are ever written to disk or into any artefact.
