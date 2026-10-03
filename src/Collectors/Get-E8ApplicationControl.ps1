<#
    Get-E8ApplicationControl.ps1
    Strategy: Application control  (Essential Eight ML1)
    Automatability: AttestationOnly

    ML1 requires execution of executables, software libraries, scripts, installers,
    compiled HTML, HTA and control panel applets to be restricted to an approved set
    in standard user profile and temp locations. True application control
    (allow-listing via WDAC/AppLocker) is enforced on the endpoint and is not
    exposed through Microsoft Graph, so this control is reported as attestation-only.
    Where Intune is licensed, Attack Surface Reduction policies are surfaced as a
    weak supporting signal only -- they are NOT application control.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] $Config,
    $License
)

$ErrorActionPreference = 'Stop'
Import-Module Microsoft.Graph.DeviceManagement -ErrorAction SilentlyContinue

$strategy = 'Application control'
$id       = 'E8-ML1-APPCTRL'
$domain   = $Config.tenant.primaryDomain
if (-not $License) { $License = Get-E8LicenseContext }

$asrSignals = @()
if ($License.intune) {
    try {
        $cfgs = @(Get-MgDeviceManagementDeviceConfiguration -All -ErrorAction Stop)
        foreach ($c in $cfgs) {
            if (("$($c.DisplayName)") -match '(?i)asr|attack surface|applocker|wdac|application control') {
                $asrSignals += [pscustomobject]@{ id=$c.Id; name=$c.DisplayName }
            }
        }
    } catch {}
}

$verdict = 'NotAssessed'
$reason  = ("Application control (allow-listing) is enforced on endpoints via WDAC/AppLocker and is " +
            "not visible through Microsoft Graph. This control is assessed by attestation. " )
if (@($asrSignals).Count -gt 0) {
    $reason += ("{0} related endpoint policy/policies were detected as a supporting signal, but these " +
                "do not by themselves satisfy ML1 application control." -f @($asrSignals).Count)
} else {
    $reason += "No supporting endpoint policy was detected via Graph."
}

return New-E8Verdict -ControlId $id -Strategy $strategy -Verdict $verdict `
    -Automatability 'AttestationOnly' -AssessmentMode 'Attestation' -TenantDomain $domain `
    -VerdictReason $reason `
    -Coverage @{ detectedTier = $License.detectedTier; supportingSignals = @($asrSignals).Count } `
    -Evidence @{ supportingPolicies = @($asrSignals); note = 'ASR != application control; included only as a weak signal.' } `
    -AttestationQuestions @(
        'Is application control implemented on workstations to restrict execution to an approved set?',
        'Does it cover executables, software libraries, scripts, installers, compiled HTML, HTA and control panel applets?',
        'Is execution restricted in standard user profile folders and temporary/OS locations where users can write?'
    )
