# QUICKSTART — Live run against a real tenant

End-to-end: from a bare machine to a finished evidence pack. Everything below is
run from `C:\E8-Toolkit`. Commands work in Windows PowerShell 5.1 or PowerShell 7.

> Safety reminder: `Invoke-E8Assessment.ps1` only reads. The only script that
> changes the tenant without further prompting is `Initialize-LabTenant.ps1`
> (creates clearly-synthetic objects). `Invoke-Lab01.ps1` deliberately weakens MFA
> and refuses to run without `-ConfirmWeaken`. Use the isolated lab tenant only.

---

## 0. Prerequisites (once per machine)
```powershell
# Microsoft Graph PowerShell SDK (the toolkit's only external dependency)
Install-Module Microsoft.Graph -Scope CurrentUser

# Modern Pester, if you want to run tests with Should -Be syntax (optional;
# the committed tests target the bundled Pester 3.4 and run as-is)
# Install-Module Pester -Scope CurrentUser -Force
```
If `Install-Module` complains about the repository, first:
`Set-PSRepository PSGallery -InstallationPolicy Trusted` (and install the NuGet
provider if prompted).

---

## 1. Prepare the lab tenant (portal, one time)
1. Microsoft 365 **Business Premium** (trial is fine). Business Standard/Basic will
   not work — no Conditional Access, Intune or Defender for Business.
2. Entra admin centre → **Properties** → **Manage security defaults** → **Disabled**
   (Security Defaults is mutually exclusive with Conditional Access).
3. Confirm you have a **break-glass / emergency access** admin account and note its
   UPN. This is the account the toolkit excludes from MFA enforcement.

---

## 2. Configure
Edit `config/lab.config.json` and remove **every** `REPLACE_ME`:
- `tenant.primaryDomain`  e.g. `SadraLabs.onmicrosoft.com`
- `tenant.tenantId`       the directory (tenant) GUID
- `breakGlass.userPrincipalName`  your emergency admin UPN

(App-only fields are only needed for unattended/scheduled runs — skip for now.)
The toolkit refuses to run while any `REPLACE_ME` remains.

---

## 3. Connect + pre-flight (sanity check)
```powershell
cd C:\E8-Toolkit
$ctx = .\scripts\Connect-E8Lab.ps1
```
A browser sign-in opens; consent to the requested scopes as a Global Admin.
The pre-flight block should print your tenant, the detected tier
(expect **Business Premium**), Conditional Access / Intune / Defender = True, and
Security Defaults = disabled. If the tenant line doesn't match, it aborts by design.

---

## 4. Seed synthetic accounts (idempotent, safe to re-run)
```powershell
.\scripts\Initialize-LabTenant.ps1
```
Creates the `E8 Lab (synthetic)` group and `e8lab01..06` users. Re-running reuses
existing objects.

---

## 5. Full safe assessment (all eight controls)
```powershell
.\Invoke-E8Assessment.ps1
```
Writes to `output/`:
- `assessment-<stamp>.json` — machine-readable, all eight controls
- `evidence-pack-<stamp>.html` — the reviewer-facing pack (open in a browser / print to PDF)

Expect MFA = NonCompliant at first (you haven't created a policy yet), the Intune
controls = Partial, and backups/app-control = NotAssessed (attestation).

---

## 6. Lab 01 — the before/after MFA evidence
```powershell
.\labs\Lab01-MFA\Invoke-Lab01.ps1 -ConfirmWeaken
```
This removes any enforcing lab MFA policy, measures (before = NonCompliant 0%),
creates `E8-Lab-01 Require MFA for all users` with the break-glass account excluded,
waits for propagation, then re-measures (after = Compliant 100%). Produces
`lab01-mfa-result.json` and `lab01-evidence-pack.html` with the transition up top.

---

## 7. Tests (optional, no tenant needed)
```powershell
Invoke-Pester -Path .\tests\E8Toolkit.Tests.ps1
```

## 8. Tear down when finished
```powershell
.\scripts\Remove-LabTenant.ps1 -WhatIf      # preview
.\scripts\Remove-LabTenant.ps1              # actually remove synthetic objects + lab policies
```

---

## Troubleshooting
| Symptom | Cause / fix |
|---------|-------------|
| "configuration still contains N placeholder value(s)" | A `REPLACE_ME` remains in `lab.config.json`. |
| "SAFETY STOP: configured primary domain ... NOT among verified domains" | Wrong tenant signed in, or `primaryDomain` typo. |
| MFA collector returns Compliant with mode `SecurityDefaults` | Security Defaults is still ON. Disable it (step 1.2) for CA-based assessment. |
| Patch/macro/hardening controls show `Blocked` / `LicensingBlocked` | Intune/Defender not licensed — a Business Standard/Basic tenant. Expected; not a failure. |
| "break-glass account ... not found" | The UPN in config isn't an enabled member user in this tenant. |
| `Connect-MgGraph` consent error | Sign in as Global Admin and grant admin consent for the listed scopes. |
