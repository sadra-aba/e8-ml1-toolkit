<#
    Get-E8OfficeMacros.ps1
    Strategy: Configure Microsoft Office macro settings  (Essential Eight ML1)
    Automatability: PartiallyAutomated  (LicensingBlocked without Intune)

    ML1 requires: macros blocked for users without a demonstrated business need;
    macros from the internet blocked; macro AV scanning enabled; users cannot
    change macro settings. In Microsoft 365 these are pushed via Intune
    (Administrative Templates / Settings Catalog). Graph can detect that a macro
    policy EXISTS and is assigned; confirming each specific setting value and that
    it is actually enforced on endpoints is attestation / device-state work.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] $Config,
    $License
)

$ErrorActionPreference = 'Stop'
Import-Module Microsoft.Graph.DeviceManagement -ErrorAction SilentlyContinue

$strategy = 'Configure Microsoft Office macro settings'
$id       = 'E8-ML1-MACROS'
$domain   = $Config.tenant.primaryDomain

if (-not $License) { $License = Get-E8LicenseContext }

if (-not $License.intune) {
    return New-E8Verdict -ControlId $id -Strategy $strategy -Verdict 'Blocked' `
        -Automatability 'LicensingBlocked' -AssessmentMode 'LicenseCheck' -TenantDomain $domain `
        -VerdictReason (("Intune is not licensed on this tenant (detected tier: {0}). Office macro " +
            "settings are enforced through Intune policy, which is unavailable at this tier. This is a " +
            "purchasing decision, not a configuration failure.") -f $License.detectedTier) `
        -Coverage @{ detectedTier = $License.detectedTier; intune = $License.intune }
}

$macroPolicies = @()
# Settings-catalog / template device configurations.
try {
    $cfgs = @(Get-MgDeviceManagementDeviceConfiguration -All -ErrorAction Stop)
    foreach ($c in $cfgs) {
        if (("$($c.DisplayName)") -match '(?i)macro') {
            $macroPolicies += [pscustomobject]@{ id=$c.Id; name=$c.DisplayName; type='deviceConfiguration' }
        }
    }
} catch {}
# ADMX (group policy) configurations.
try {
    $gps = @(Get-MgDeviceManagementGroupPolicyConfiguration -All -ErrorAction Stop)
    foreach ($g in $gps) {
        if (("$($g.DisplayName)") -match '(?i)macro|office') {
            $macroPolicies += [pscustomobject]@{ id=$g.Id; name=$g.DisplayName; type='groupPolicyConfiguration' }
        }
    }
} catch {}

$found = @($macroPolicies).Count

$verdict = 'NonCompliant'
if ($found -eq 0) {
    $verdict = 'NonCompliant'
    $reason  = ("No Intune policy referencing Office macro settings was found. ML1 requires macros " +
                "(especially from the internet) to be blocked by enforced policy.")
} else {
    $verdict = 'Partial'
    $reason  = (("{0} Intune policy/policies referencing Office macros were found. Policy existence is " +
                "confirmed; that each ML1 macro setting (block internet macros, AV scanning, users " +
                "cannot change settings) is set correctly and enforced on endpoints requires device-state " +
                "review or attestation.") -f $found)
}

return New-E8Verdict -ControlId $id -Strategy $strategy -Verdict $verdict `
    -Automatability 'PartiallyAutomated' -AssessmentMode 'Intune' -TenantDomain $domain `
    -VerdictReason $reason `
    -Coverage @{ detectedTier = $License.detectedTier; macroPoliciesFound = $found } `
    -Evidence @{ policies = @($macroPolicies) } `
    -AttestationQuestions @(
        'Are Office macros blocked for all users who do not have a demonstrated business requirement?',
        'Are Office macros originating from the internet blocked?',
        'Is antivirus scanning of Office macros enabled?',
        'Are users prevented from changing Office macro security settings?'
    )
