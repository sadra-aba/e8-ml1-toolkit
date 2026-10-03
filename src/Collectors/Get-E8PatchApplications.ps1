<#
    Get-E8PatchApplications.ps1
    Strategy: Patch applications  (Essential Eight ML1)
    Automatability: PartiallyAutomated  (LicensingBlocked without Intune/Defender)

    ML1 asks that application patches / vulnerable apps are remediated within the
    required windows and that an automated method of asset discovery and a
    vulnerability scanner are used.

    Graph-assessable signals on Business Premium:
      * Intune-managed device inventory (asset discovery is in place),
      * presence of update/compliance configuration.
    Richer vulnerability-age data lives in Defender for Business TVM (noted as the
    preferred future source). Where neither Intune nor Defender is licensed, the
    control is reported LicensingBlocked, not NonCompliant.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] $Config,
    $License
)

$ErrorActionPreference = 'Stop'
Import-Module Microsoft.Graph.DeviceManagement -ErrorAction SilentlyContinue

$strategy = 'Patch applications'
$id       = 'E8-ML1-PATCHAPP'
$domain   = $Config.tenant.primaryDomain

if (-not $License) { $License = Get-E8LicenseContext }

if (-not $License.intune -and -not $License.defenderForBusiness) {
    return New-E8Verdict -ControlId $id -Strategy $strategy -Verdict 'Blocked' `
        -Automatability 'LicensingBlocked' -AssessmentMode 'LicenseCheck' -TenantDomain $domain `
        -VerdictReason (("Neither Intune nor Defender for Business is licensed on this tenant " +
            "(detected tier: {0}). Automated application patch assessment cannot be performed. " +
            "This is a purchasing decision, not a configuration failure.") -f $License.detectedTier) `
        -Coverage @{ detectedTier = $License.detectedTier; intune = $License.intune; defenderForBusiness = $License.defenderForBusiness }
}

$deviceCount = 0
$compliancePolicies = 0
$assetDiscovery = $false
try {
    $devices = @(Get-MgDeviceManagementManagedDevice -All -ErrorAction Stop)
    $deviceCount = $devices.Count
    $assetDiscovery = ($deviceCount -gt 0)
} catch {}
try {
    $cps = @(Get-MgDeviceManagementDeviceCompliancePolicy -All -ErrorAction Stop)
    $compliancePolicies = $cps.Count
} catch {}

$verdict = 'Partial'
if (-not $assetDiscovery) {
    $verdict = 'NonCompliant'
    $reason  = ("Intune is licensed but no managed devices were found, so there is no automated " +
                "asset discovery to drive application patching. Enrol devices and confirm patch windows.")
} else {
    $verdict = 'Partial'
    $reason  = (("{0} Intune-managed device(s) and {1} compliance policy/policies provide asset " +
                "discovery and a configuration baseline. Patch-age evidence (apps patched within the " +
                "ML1 window) requires Defender for Business TVM data or attestation.") -f $deviceCount, $compliancePolicies)
}

return New-E8Verdict -ControlId $id -Strategy $strategy -Verdict $verdict `
    -Automatability 'PartiallyAutomated' -AssessmentMode 'Intune' -TenantDomain $domain `
    -VerdictReason $reason `
    -Coverage @{
        detectedTier       = $License.detectedTier
        managedDevices     = $deviceCount
        compliancePolicies = $compliancePolicies
        assetDiscovery     = $assetDiscovery
    } `
    -Evidence @{
        note = 'Preferred richer source: Defender for Business Threat & Vulnerability Management (exposure + patch age).'
    } `
    -AttestationQuestions @(
        'Are application patches/updates for internet-facing and productivity apps applied within two weeks (48 hours if a working exploit exists)?',
        'Is a vulnerability scanner with an up-to-date database used at least fortnightly to identify missing patches?',
        'Are applications that are no longer supported by the vendor removed?'
    )
