<#
    Get-E8RestrictAdminPrivileges.ps1
    Strategy: Restrict administrative privileges  (Essential Eight ML1)
    Automatability: PartiallyAutomated

    What CAN be assessed from Graph:
      * inventory of accounts holding privileged directory roles,
      * the number of Global Administrators (Microsoft guidance: keep it small,
        typically <= 4 plus break-glass),
      * whether privileged accounts appear to be separate, cloud-only accounts.

    What CANNOT be assessed from Graph (-> attestation questions):
      * that privileged access is validated when first requested,
      * that privileged accounts are blocked from internet/email/web,
      * that privileged and unprivileged operating environments are separated.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] $Config
)

$ErrorActionPreference = 'Stop'
Import-Module Microsoft.Graph.Identity.DirectoryManagement -ErrorAction SilentlyContinue
Import-Module Microsoft.Graph.Users -ErrorAction SilentlyContinue

$strategy = 'Restrict administrative privileges'
$id       = 'E8-ML1-ADMIN'
$domain   = $Config.tenant.primaryDomain

# Privileged roles of interest (display names as surfaced by directoryRoles).
$privilegedRoles = @(
    'Global Administrator','Privileged Role Administrator','Privileged Authentication Administrator',
    'Security Administrator','Exchange Administrator','SharePoint Administrator',
    'User Administrator','Conditional Access Administrator','Application Administrator',
    'Cloud Application Administrator','Intune Administrator','Authentication Administrator',
    'Helpdesk Administrator','Billing Administrator'
)

$roles = @(Get-MgDirectoryRole -All -ErrorAction Stop)
$inventory = @()
$gaMembers = @()

foreach ($r in $roles) {
    if ($privilegedRoles -notcontains $r.DisplayName) { continue }
    $members = @()
    try { $members = @(Get-MgDirectoryRoleMember -DirectoryRoleId $r.Id -All -ErrorAction Stop) } catch {}
    foreach ($m in $members) {
        $upn = $null; $disp = $null
        try { $upn = $m.AdditionalProperties.userPrincipalName } catch {}
        try { $disp = $m.AdditionalProperties.displayName } catch {}
        $entry = [pscustomobject]@{
            role              = $r.DisplayName
            id                = $m.Id
            displayName       = $disp
            userPrincipalName = $upn
        }
        $inventory += $entry
        if ($r.DisplayName -eq 'Global Administrator') { $gaMembers += $entry }
    }
}

$gaCount = @($gaMembers).Count
$distinctPrivileged = @($inventory | Select-Object -ExpandProperty id -Unique).Count

# Automated signal: Global Administrator count.
# Microsoft/ASD guidance favours a small number of GAs. Treat >4 as a finding.
$gaThreshold = 4
$signalFail = ($gaCount -gt $gaThreshold)

$verdict = 'Partial'
if ($gaCount -eq 0) {
    $verdict = 'NonCompliant'
    $reason  = ("No Global Administrator accounts were found, which is unexpected and suggests the " +
                "assessment could not read role membership.")
} elseif ($signalFail) {
    $verdict = 'NonCompliant'
    $reason  = (("{0} accounts hold Global Administrator, exceeding the guidance ceiling of {1}. " +
                "Excess standing privilege increases the administrative attack surface. " +
                "Remaining ML1 requirements are process-based and require attestation.") -f $gaCount, $gaThreshold)
} else {
    $verdict = 'Partial'
    $reason  = (("{0} Global Administrator account(s) and {1} distinct privileged account(s) were " +
                "inventoried, within the guidance ceiling. The automatable portion looks sound; the " +
                "ML1 process requirements below require attestation before this control can be called met.") `
                -f $gaCount, $distinctPrivileged)
}

return New-E8Verdict -ControlId $id -Strategy $strategy -Verdict $verdict `
    -Automatability 'PartiallyAutomated' -AssessmentMode 'RoleInventory' -TenantDomain $domain `
    -VerdictReason $reason `
    -Coverage @{
        globalAdministrators = $gaCount
        globalAdminCeiling   = $gaThreshold
        distinctPrivileged   = $distinctPrivileged
        privilegedRolesSeen  = @($inventory | Select-Object -ExpandProperty role -Unique)
    } `
    -Evidence @{
        globalAdmins       = @($gaMembers)
        privilegedAccounts = @($inventory)
    } `
    -AttestationQuestions @(
        'Are requests for new privileged access validated before being granted?',
        'Are privileged accounts prevented from accessing the internet, email and web services?',
        'Do administrators use separate privileged and unprivileged accounts (no day-to-day use of admin accounts)?'
    )
