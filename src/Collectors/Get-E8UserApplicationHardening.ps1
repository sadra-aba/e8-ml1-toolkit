<#
    Get-E8UserApplicationHardening.ps1
    Strategy: User application hardening  (Essential Eight ML1)
    Automatability: PartiallyAutomated  (LicensingBlocked without Intune)

    ML1 requires: web browsers do not process Java from the internet; web browsers
    do not process web advertisements from the internet; Internet Explorer 11 is
    disabled or removed; browser security settings cannot be changed by users.
    Enforced via Intune browser/ADMX policy. Graph can detect that a relevant
    policy exists; value-level and endpoint enforcement is attestation.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] $Config,
    $License
)

$ErrorActionPreference = 'Stop'
Import-Module Microsoft.Graph.DeviceManagement -ErrorAction SilentlyContinue

$strategy = 'User application hardening'
$id       = 'E8-ML1-HARDEN'
$domain   = $Config.tenant.primaryDomain

if (-not $License) { $License = Get-E8LicenseContext }

if (-not $License.intune) {
    return New-E8Verdict -ControlId $id -Strategy $strategy -Verdict 'Blocked' `
        -Automatability 'LicensingBlocked' -AssessmentMode 'LicenseCheck' -TenantDomain $domain `
        -VerdictReason ("Intune is not licensed on this tenant (detected tier: {0}). Browser and user " +
            "application hardening is enforced through Intune policy, unavailable at this tier. This is a " +
            "purchasing decision, not a configuration failure." -f $License.detectedTier) `
        -Coverage @{ detectedTier = $License.detectedTier; intune = $License.intune }
}

$hardeningPolicies = @()
$pattern = '(?i)browser|edge|chrome|java|internet explorer|\bie11\b|hardening|attack surface|asr'
try {
    $cfgs = @(Get-MgDeviceManagementDeviceConfiguration -All -ErrorAction Stop)
    foreach ($c in $cfgs) {
        if (("$($c.DisplayName)") -match $pattern) {
            $hardeningPolicies += [pscustomobject]@{ id=$c.Id; name=$c.DisplayName; type='deviceConfiguration' }
        }
    }
} catch {}
try {
    $gps = @(Get-MgDeviceManagementGroupPolicyConfiguration -All -ErrorAction Stop)
    foreach ($g in $gps) {
        if (("$($g.DisplayName)") -match $pattern) {
            $hardeningPolicies += [pscustomobject]@{ id=$g.Id; name=$g.DisplayName; type='groupPolicyConfiguration' }
        }
    }
} catch {}

$found = @($hardeningPolicies).Count
$verdict = 'NonCompliant'
if ($found -eq 0) {
    $verdict = 'NonCompliant'
    $reason  = ("No Intune policy relating to browser/user application hardening was found. ML1 requires " +
                "browsers to block internet Java and web ads, IE11 disabled, and locked browser settings.")
} else {
    $verdict = 'Partial'
    $reason  = ("{0} candidate hardening policy/policies were found. Existence is confirmed; that the " +
                "specific ML1 settings are applied and enforced on endpoints requires device-state review " +
                "or attestation." -f $found)
}

return New-E8Verdict -ControlId $id -Strategy $strategy -Verdict $verdict `
    -Automatability 'PartiallyAutomated' -AssessmentMode 'Intune' -TenantDomain $domain `
    -VerdictReason $reason `
    -Coverage @{ detectedTier = $License.detectedTier; hardeningPoliciesFound = $found } `
    -Evidence @{ policies = @($hardeningPolicies) } `
    -AttestationQuestions @(
        'Are web browsers configured so they do not process Java from the internet?',
        'Are web browsers configured so they do not process web advertisements from the internet?',
        'Is Internet Explorer 11 disabled or removed?',
        'Are users prevented from changing web browser security settings?'
    )
