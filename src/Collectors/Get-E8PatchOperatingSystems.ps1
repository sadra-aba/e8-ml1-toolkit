<#
    Get-E8PatchOperatingSystems.ps1
    Strategy: Patch operating systems  (Essential Eight ML1)
    Automatability: PartiallyAutomated  (LicensingBlocked without Intune)

    Graph-assessable signals on Business Premium:
      * Intune-managed device inventory and OS versions,
      * presence of a Windows update ring / update policy.
    ML1 requires OS patches applied within one month (two weeks for internet-facing)
    and that unsupported operating systems are replaced. Patch-age confirmation
    needs device update state; the rest is attestation.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] $Config,
    $License
)

$ErrorActionPreference = 'Stop'
Import-Module Microsoft.Graph.DeviceManagement -ErrorAction SilentlyContinue

$strategy = 'Patch operating systems'
$id       = 'E8-ML1-PATCHOS'
$domain   = $Config.tenant.primaryDomain

if (-not $License) { $License = Get-E8LicenseContext }

if (-not $License.intune) {
    return New-E8Verdict -ControlId $id -Strategy $strategy -Verdict 'Blocked' `
        -Automatability 'LicensingBlocked' -AssessmentMode 'LicenseCheck' -TenantDomain $domain `
        -VerdictReason (("Intune is not licensed on this tenant (detected tier: {0}), so operating " +
            "system patch state cannot be assessed centrally. This is a purchasing decision, not a " +
            "configuration failure.") -f $License.detectedTier) `
        -Coverage @{ detectedTier = $License.detectedTier; intune = $License.intune }
}

$deviceCount = 0
$osSummary = @{}
$updatePolicies = 0
try {
    $devices = @(Get-MgDeviceManagementManagedDevice -All -ErrorAction Stop)
    $deviceCount = $devices.Count
    foreach ($d in $devices) {
        $os = $d.OperatingSystem
        if (-not $os) { $os = 'Unknown' }
        if ($osSummary.ContainsKey($os)) { $osSummary[$os]++ } else { $osSummary[$os] = 1 }
    }
} catch {}
try {
    # Windows update rings surface as deviceConfigurations of the update type.
    $cfgs = @(Get-MgDeviceManagementDeviceConfiguration -All -ErrorAction Stop)
    $updatePolicies = @($cfgs | Where-Object { $_.AdditionalProperties.'@odata.type' -match 'windowsUpdate' }).Count
} catch {}

$verdict = 'Partial'
if ($deviceCount -eq 0) {
    $verdict = 'NonCompliant'
    $reason  = "Intune is licensed but no managed devices were found, so OS patch state cannot be confirmed. Enrol devices."
} elseif ($updatePolicies -eq 0) {
    $verdict = 'Partial'
    $reason  = (("{0} managed device(s) are enrolled but no Windows update ring/policy was detected. " +
                "Without a managed update policy, patch windows rely on local configuration and attestation.") -f $deviceCount)
} else {
    $verdict = 'Partial'
    $reason  = (("{0} managed device(s) and {1} update policy/policies are present, giving central OS " +
                "patch management. Confirmation that patches meet the ML1 windows and that no " +
                "unsupported OS remains requires device update-state review or attestation.") -f $deviceCount, $updatePolicies)
}

return New-E8Verdict -ControlId $id -Strategy $strategy -Verdict $verdict `
    -Automatability 'PartiallyAutomated' -AssessmentMode 'Intune' -TenantDomain $domain `
    -VerdictReason $reason `
    -Coverage @{
        detectedTier    = $License.detectedTier
        managedDevices  = $deviceCount
        updatePolicies  = $updatePolicies
        osBreakdown     = $osSummary
    } `
    -Evidence @{
        note = 'Device-level update compliance state is the preferred patch-age evidence source.'
    } `
    -AttestationQuestions @(
        'Are operating system patches applied within one month of release (two weeks for internet-facing services)?',
        'Are operating systems that are no longer supported by the vendor replaced?'
    )
