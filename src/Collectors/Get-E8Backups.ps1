<#
    Get-E8Backups.ps1
    Strategy: Regular backups  (Essential Eight ML1)
    Automatability: AttestationOnly

    ML1 requires backups of important data, software and configuration performed
    and retained per business continuity requirements; backups synchronised to
    enable restoration to a common point in time; and restoration tested as part of
    disaster recovery exercises. A Microsoft 365 tenant's native retention/litigation
    hold is NOT a backup, and whether a separate backup regime exists and is tested
    cannot be determined from Graph. Reported as attestation-only.

    Where available, Exchange/SharePoint retention policies are surfaced as context
    only, with an explicit statement that retention is not backup.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] $Config,
    $License
)

$ErrorActionPreference = 'Stop'

$strategy = 'Regular backups'
$id       = 'E8-ML1-BACKUP'
$domain   = $Config.tenant.primaryDomain
if (-not $License) { $License = Get-E8LicenseContext }

return New-E8Verdict -ControlId $id -Strategy $strategy -Verdict 'NotAssessed' `
    -Automatability 'AttestationOnly' -AssessmentMode 'Attestation' -TenantDomain $domain `
    -VerdictReason ("Whether important data, software and configuration are backed up, retained and " +
        "test-restored cannot be determined from the Microsoft 365 tenant configuration. Native " +
        "retention and litigation hold are not backups. This control is assessed by attestation.") `
    -Coverage @{ detectedTier = $License.detectedTier } `
    -Evidence @{ note = 'Microsoft 365 retention/litigation hold is not a substitute for backup and is not counted here.' } `
    -AttestationQuestions @(
        'Are backups of important data, software and configuration performed and retained per business continuity requirements?',
        'Are backups synchronised to enable restoration to a common point in time?',
        'Is restoration of backups tested as part of disaster recovery exercises?',
        'Are unprivileged accounts prevented from accessing, modifying or deleting backups of other accounts?'
    )
