<#
    Get-E8MfaCoverage.ps1
    Strategy: Multi-factor authentication  (Essential Eight ML1)
    Automatability: Automated

    Reports MFA coverage across the assessable population. Assessment-only:
    reads policy and user state, never modifies the tenant.

    Logic:
      * If Security Defaults is ENABLED -> Compliant (mode=SecurityDefaults): a
        tenant on Security Defaults enforces MFA for all users and satisfies ML1,
        but cannot be assessed at policy granularity. Avoids the false negative a
        naive "no CA policy => NonCompliant" check would produce.
      * Otherwise resolve enabled CA policies that require MFA for all cloud apps,
        compute covered assessable users, and grade coverage.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] $Config,
    [Nullable[bool]] $SecurityDefaultsEnabled
)

$ErrorActionPreference = 'Stop'
Import-Module Microsoft.Graph.Identity.SignIns -ErrorAction SilentlyContinue
Import-Module Microsoft.Graph.Users -ErrorAction SilentlyContinue
Import-Module Microsoft.Graph.Groups -ErrorAction SilentlyContinue

$strategy = 'Multi-factor authentication'
$id       = 'E8-ML1-MFA'
$domain   = $Config.tenant.primaryDomain

# --- population ---
$pop = Get-E8AssessablePopulation -Config $Config
$assessable = @($pop.Assessable)
$assessableCount = $assessable.Count

# --- Security Defaults branch ---
if ($null -eq $SecurityDefaultsEnabled) { $SecurityDefaultsEnabled = Get-E8SecurityDefaultsState }

if ($SecurityDefaultsEnabled -eq $true) {
    return New-E8Verdict -ControlId $id -Strategy $strategy -Verdict 'Compliant' `
        -Automatability 'Automated' -AssessmentMode 'SecurityDefaults' -TenantDomain $domain `
        -VerdictReason ("Security Defaults is enabled, which enforces multi-factor authentication " +
            "registration and challenge for all users. The ML1 MFA requirement is met. " +
            "Granular per-policy assessment does not apply while Security Defaults is on.") `
        -Coverage @{
            mode                 = 'SecurityDefaults'
            totalEnabledMembers  = @($pop.EnabledMembers).Count
            assessableAccounts   = $assessableCount
            coveredAccounts      = $assessableCount
            coveragePercent      = 100
            enforcingPolicies    = 0
        } `
        -Evidence @{
            breakGlassAccount    = $pop.BreakGlass.UserPrincipalName
            note                 = 'Security Defaults supersedes Conditional Access policy evaluation.'
        }
}

# --- Conditional Access branch ---
$caPolicies = @(Get-MgIdentityConditionalAccessPolicy -All -ErrorAction Stop)
$enforcing  = @($caPolicies | Where-Object { Test-E8CaPolicyRequiresMfa -Policy $_ })

$coveredIds   = [System.Collections.Generic.HashSet[string]]::new()
$unresolved   = @()
$policyDetails = @()

foreach ($p in $enforcing) {
    $res = Resolve-E8CaCoveredUserIds -Policy $p -AssessableUsers $assessable
    foreach ($cid in $res.CoveredIds) { [void]$coveredIds.Add($cid) }
    foreach ($u in $res.Unresolved) { $unresolved += $u }
    $policyDetails += [pscustomobject]@{
        id    = $p.Id
        name  = $p.DisplayName
        state = $p.State
        covered = @($res.CoveredIds).Count
    }
}

$covered = @($assessable | Where-Object { $coveredIds.Contains($_.Id) })
$coveredCount = $covered.Count
$uncovered = @($assessable | Where-Object { -not $coveredIds.Contains($_.Id) })

$pct = 0
if ($assessableCount -gt 0) { $pct = [math]::Round(($coveredCount / $assessableCount) * 100, 0) }

# --- verdict ---
$verdict = 'NonCompliant'
$reason  = ''
if ($enforcing.Count -eq 0) {
    $verdict = 'NonCompliant'
    $reason  = ("No enabled Conditional Access policy requires multi-factor authentication. " +
                "All user sign-ins can complete with a password alone.")
} elseif ($pct -ge 100) {
    $verdict = 'Compliant'
    $reason  = ("All {0} assessable account(s) are covered by an enabled Conditional Access " +
                "policy requiring multi-factor authentication." -f $assessableCount)
} elseif ($pct -gt 0) {
    $verdict = 'Partial'
    $reason  = ("{0} of {1} assessable account(s) are covered by an MFA-enforcing Conditional " +
                "Access policy; {2} remain uncovered." -f $coveredCount, $assessableCount, $uncovered.Count)
} else {
    $verdict = 'NonCompliant'
    $reason  = ("An MFA-enforcing policy exists but covers none of the {0} assessable accounts." -f $assessableCount)
}
if ($unresolved.Count -gt 0) {
    $reason += (" NOTE: {0} policy target(s) could not be resolved and were not assumed covered." -f $unresolved.Count)
}

return New-E8Verdict -ControlId $id -Strategy $strategy -Verdict $verdict `
    -Automatability 'Automated' -AssessmentMode 'ConditionalAccess' -TenantDomain $domain `
    -VerdictReason $reason `
    -Coverage @{
        mode                = 'ConditionalAccess'
        totalEnabledMembers = @($pop.EnabledMembers).Count
        assessableAccounts  = $assessableCount
        coveredAccounts     = $coveredCount
        coveragePercent     = $pct
        enforcingPolicies   = $enforcing.Count
    } `
    -Evidence @{
        breakGlassAccount = $pop.BreakGlass.UserPrincipalName
        enforcingPolicies = @($policyDetails)
        uncoveredUsers    = @($uncovered | ForEach-Object {
            [pscustomobject]@{ displayName = $_.DisplayName; userPrincipalName = $_.UserPrincipalName } })
        unresolvedTargets = @($unresolved)
    }
