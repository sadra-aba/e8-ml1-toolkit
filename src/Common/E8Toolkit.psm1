<#
    E8Toolkit.psm1
    Shared primitives for the Essential Eight Maturity Level 1 assessment toolkit.

    Design rules (see docs/RUNBOOK.md and the Milestone B report):
      * Collectors assess only. Nothing in this module writes to the tenant.
      * Every collector returns the SAME verdict shape via New-E8Verdict.
      * "Blocked" (cannot be assessed/configured at this licensing tier) is never
        conflated with "NonCompliant" (assessable, and failing).
      * Runs on BOTH Windows PowerShell 5.1 and PowerShell 7 — so no ternary,
        no null-coalescing, no 3-arg Join-Path, and array context is forced with @().
#>

Set-StrictMode -Version 2.0

# --- Enumerated string values (documented, not enforced as [enum] for 5.1 friendliness) ---
# Verdict        : Compliant | Partial | NonCompliant | Blocked | NotAssessed
# Automatability : Automated | PartiallyAutomated | AttestationOnly | LicensingBlocked

function Get-E8Config {
    <#
        Loads lab.config.json and refuses to proceed while placeholder values remain.
        T-requirement: validate that no placeholder values remain before any run.
    #>
    [CmdletBinding()]
    param(
        [string] $Path
    )

    if (-not $Path) {
        $root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
        $Path = [IO.Path]::Combine($root, 'config', 'lab.config.json')
    }
    if (-not (Test-Path -LiteralPath $Path)) {
        throw "E8: configuration file not found at '$Path'."
    }

    $raw = Get-Content -LiteralPath $Path -Raw
    $cfg = $raw | ConvertFrom-Json

    $placeholders = [regex]::Matches($raw, 'REPLACE_ME')
    if ($placeholders.Count -gt 0) {
        throw (("E8: configuration still contains {0} placeholder value(s) (REPLACE_ME). " +
               "Edit '{1}' before running.") -f $placeholders.Count, $Path)
    }

    # Normalise output directory to an absolute path.
    $root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    if ($cfg.output.directory -match '^\.') {
        $cfg.output | Add-Member -NotePropertyName 'resolvedDirectory' `
            -NotePropertyValue ([IO.Path]::GetFullPath([IO.Path]::Combine($root, $cfg.output.directory))) -Force
    } else {
        $cfg.output | Add-Member -NotePropertyName 'resolvedDirectory' `
            -NotePropertyValue $cfg.output.directory -Force
    }

    return $cfg
}

function Get-E8ScopeList {
    <# Least-privilege delegated scopes, requested explicitly. #>
    [CmdletBinding()]
    param()
    return @(
        'User.ReadWrite.All',                  # seed and read synthetic users
        'Group.ReadWrite.All',                 # seed the lab group
        'Directory.Read.All',                  # tenant and role context
        'Policy.Read.All',                     # read conditional access + authorisation policy
        'Policy.ReadWrite.ConditionalAccess',  # create lab policies (remediation only)
        'Application.Read.All',                 # policy target resolution
        'RoleManagement.Read.Directory',       # admin role assignment (restrict admin privileges)
        'Organization.Read.All',               # licensing / SKU detection
        'DeviceManagementConfiguration.Read.All',   # Intune profiles (macros, hardening)
        'DeviceManagementManagedDevices.Read.All'   # Intune device/update state (patching)
    )
}

function Get-E8ReadOnlyScopeList {
    <# Scopes sufficient for assessment WITHOUT remediation. A least-privilege
       client can grant these and withhold Policy.ReadWrite.ConditionalAccess. #>
    [CmdletBinding()]
    param()
    return @(Get-E8ScopeList | Where-Object { $_ -notmatch 'ReadWrite' })
}

function Get-E8NowUtc {
    param()
    return (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
}

function New-E8Verdict {
    <#
        The single canonical collector return shape. Every collector MUST build
        its result with this function so the evidence pack can render uniformly.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string] $ControlId,
        [Parameter(Mandatory)][string] $Strategy,
        [int] $MaturityLevel = 1,
        [Parameter(Mandatory)][ValidateSet('Compliant','Partial','NonCompliant','Blocked','NotAssessed')]
        [string] $Verdict,
        [Parameter(Mandatory)][string] $VerdictReason,
        [Parameter(Mandatory)][ValidateSet('Automated','PartiallyAutomated','AttestationOnly','LicensingBlocked')]
        [string] $Automatability,
        [string] $AssessmentMode = 'Graph',
        [hashtable] $Coverage,
        [hashtable] $Evidence,
        [string[]] $AttestationQuestions,
        [string] $TenantDomain
    )

    if (-not $Coverage) { $Coverage = @{} }
    if (-not $Evidence) { $Evidence = @{} }

    return [pscustomobject][ordered]@{
        controlId            = $ControlId
        strategy             = $Strategy
        maturityLevel        = $MaturityLevel
        verdict              = $Verdict
        verdictReason        = $VerdictReason
        automatability       = $Automatability
        assessmentMode       = $AssessmentMode
        coverage             = $Coverage
        evidence             = $Evidence
        attestationQuestions = @($AttestationQuestions)
        tenantDomain         = $TenantDomain
        collectedUtc         = (Get-E8NowUtc)
    }
}

function Assert-E8Tenant {
    <#
        Safety control: refuse to proceed unless the signed-in tenant's verified
        domains include the configured primary domain. The toolkit deliberately
        weakens controls, so running it against the wrong tenant would be serious.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Config)

    $org = Get-MgOrganization -ErrorAction Stop
    $verified = @()
    foreach ($o in @($org)) {
        foreach ($d in @($o.VerifiedDomains)) { $verified += $d.Name }
    }
    $want = $Config.tenant.primaryDomain
    if ($verified -notcontains $want) {
        throw (("E8 SAFETY STOP: configured primary domain '{0}' is NOT among the " +
               "signed-in tenant's verified domains ({1}). Aborting.") -f $want, ($verified -join ', '))
    }
    Write-Verbose "Tenant verified: '$want' present in signed-in tenant."
    return $true
}

function Get-E8SecurityDefaultsState {
    <# Returns $true/$false for Security Defaults. Blocks Conditional Access when enabled. #>
    [CmdletBinding()]
    param()
    try {
        $p = Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy -ErrorAction Stop
        return [bool] $p.IsEnabled
    } catch {
        Write-Verbose "Could not read Security Defaults policy: $($_.Exception.Message)"
        return $null
    }
}

function Get-E8LicenseContext {
    <#
        Inspects subscribed SKUs to decide which capabilities are LICENSED, so a
        control that is simply unavailable at this tier is reported LicensingBlocked
        rather than NonCompliant.

        Capability -> licensing source (Business Premium includes all three):
          ConditionalAccess  <- Entra ID P1   (SKU: SPB, EMS*, AAD_PREMIUM*)
          Intune             <- Intune         (SKU: SPB, INTUNE_A, EMS*)
          DefenderBusiness   <- Defender for Business (SKU: SPB, DEFENDER_ENDPOINT*)
    #>
    [CmdletBinding()]
    param()

    $skuParts = @()
    try {
        $skus = Get-MgSubscribedSku -ErrorAction Stop
        foreach ($s in @($skus)) { $skuParts += $s.SkuPartNumber }
    } catch {
        Write-Verbose "Could not read subscribed SKUs: $($_.Exception.Message)"
    }

    $hasPremium = @($skuParts | Where-Object { $_ -eq 'SPB' }).Count -gt 0
    $hasEntraP1 = $hasPremium -or @($skuParts | Where-Object {
        $_ -match 'AAD_PREMIUM|EMS|SPE_' }).Count -gt 0
    $hasIntune  = $hasPremium -or @($skuParts | Where-Object {
        $_ -match 'INTUNE|EMS|SPE_' }).Count -gt 0
    $hasDefB    = $hasPremium -or @($skuParts | Where-Object {
        $_ -match 'DEFENDER|MDATP|SPE_E5|_E5' }).Count -gt 0

    $tier = 'Unknown'
    if ($hasPremium) { $tier = 'Business Premium' }
    elseif (@($skuParts | Where-Object { $_ -eq 'O365_BUSINESS_PREMIUM' }).Count -gt 0) { $tier = 'Business Standard' }
    elseif (@($skuParts | Where-Object { $_ -eq 'O365_BUSINESS_ESSENTIALS' }).Count -gt 0) { $tier = 'Business Basic' }

    return [pscustomobject][ordered]@{
        detectedTier          = $tier
        skuPartNumbers        = @($skuParts)
        conditionalAccess     = [bool]$hasEntraP1
        intune                = [bool]$hasIntune
        defenderForBusiness   = [bool]$hasDefB
    }
}

function Get-E8AssessablePopulation {
    <#
        Enabled MEMBER users minus the break-glass account. The break-glass
        account is intentionally excluded from MFA enforcement, so counting it
        would distort coverage in either direction.
        Returns @{ EnabledMembers=[]; BreakGlass=obj; Assessable=[] }.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Config)

    $users = Get-MgUser -All -Property 'Id,DisplayName,UserPrincipalName,AccountEnabled,UserType' -ErrorAction Stop
    $enabledMembers = @($users | Where-Object { $_.AccountEnabled -eq $true -and $_.UserType -eq 'Member' })

    $bgUpn = $Config.breakGlass.userPrincipalName
    $bg = $enabledMembers | Where-Object { $_.UserPrincipalName -eq $bgUpn } | Select-Object -First 1
    if (-not $bg) {
        throw (("E8 SAFETY STOP: break-glass account '{0}' not found among enabled member users. " +
               "Cannot safely proceed.") -f $bgUpn)
    }

    $assessable = @($enabledMembers | Where-Object { $_.Id -ne $bg.Id })
    return [pscustomobject]@{
        EnabledMembers = $enabledMembers
        BreakGlass     = $bg
        Assessable     = $assessable
    }
}

function Resolve-E8CaCoveredUserIds {
    <#
        Given a Conditional Access policy object and the assessable user set,
        returns the set of assessable user IDs the policy actually covers.
        Handles include all/users/groups and the matching excludes; expands
        group membership; surfaces any inclusion it could not resolve.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Policy,
        [Parameter(Mandatory)] $AssessableUsers
    )

    $assessableIds = @($AssessableUsers | ForEach-Object { $_.Id })
    $cond = $Policy.Conditions.Users
    $unresolved = @()

    # --- includes ---
    $included = [System.Collections.Generic.HashSet[string]]::new()
    if (@($cond.IncludeUsers) -contains 'All') {
        foreach ($id in $assessableIds) { [void]$included.Add($id) }
    } else {
        foreach ($u in @($cond.IncludeUsers)) {
            if ($u -and $u -ne 'None' -and $u -ne 'GuestsOrExternalUsers') { [void]$included.Add($u) }
        }
        foreach ($g in @($cond.IncludeGroups)) {
            try {
                $members = Get-MgGroupMember -GroupId $g -All -ErrorAction Stop
                foreach ($m in @($members)) { [void]$included.Add($m.Id) }
            } catch {
                $unresolved += "group:$g"
            }
        }
    }

    # --- excludes ---
    $excluded = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($u in @($cond.ExcludeUsers)) { if ($u) { [void]$excluded.Add($u) } }
    foreach ($g in @($cond.ExcludeGroups)) {
        try {
            $members = Get-MgGroupMember -GroupId $g -All -ErrorAction Stop
            foreach ($m in @($members)) { [void]$excluded.Add($m.Id) }
        } catch {
            $unresolved += "excludeGroup:$g"
        }
    }

    $covered = @($assessableIds | Where-Object { $included.Contains($_) -and -not $excluded.Contains($_) })
    return [pscustomobject]@{
        CoveredIds = @($covered)
        Unresolved = @($unresolved)
    }
}

function Test-E8CaPolicyRequiresMfa {
    <# True if an enabled CA policy grants via MFA for all cloud apps. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Policy)

    if ($Policy.State -ne 'enabled') { return $false }
    $apps = @($Policy.Conditions.Applications.IncludeApplications)
    if ($apps -notcontains 'All') { return $false }
    $controls = @($Policy.GrantControls.BuiltInControls)
    return ($controls -contains 'mfa')
}

function New-E8SyntheticPassword {
    <#
        Cryptographically-random synthetic password for lab seeding.
        Used once at creation; never written to disk/console/evidence (T8).
        PS 5.1 (.NET Framework) falls back to RNGCryptoServiceProvider;
        PS 7 (.NET Core) uses RandomNumberGenerator.
    #>
    [CmdletBinding()]
    param([int] $Length = 24)

    $bytes = New-Object 'byte[]' $Length
    $filled = $false
    try {
        [System.Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
        $filled = $true
    } catch { $filled = $false }
    if (-not $filled) {
        $rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
        try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
    }

    $alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789!@#$%^&*'
    $sb = New-Object System.Text.StringBuilder
    foreach ($b in $bytes) { [void]$sb.Append($alphabet[$b % $alphabet.Length]) }
    # Guarantee complexity classes.
    return ('Aa1!' + $sb.ToString())
}

function Wait-E8Condition {
    <#
        Poll a read-only predicate until it returns $true or a timeout elapses.
        Replaces fixed Start-Sleep waits for directory propagation: we wait only as
        long as needed and no longer. The predicate must NOT modify the tenant.
        Returns $true if the condition was met, $false on timeout.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][scriptblock] $Condition,
        [int] $TimeoutSeconds = 120,
        [int] $PollSeconds = 5,
        [string] $Activity = 'Waiting for directory propagation'
    )
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    $attempt = 0
    while ((Get-Date) -lt $deadline) {
        $attempt++
        $ok = $false
        try { $ok = [bool](& $Condition) } catch { $ok = $false }
        if ($ok) {
            Write-Verbose ("{0}: met after {1} attempt(s)." -f $Activity, $attempt)
            return $true
        }
        Start-Sleep -Seconds $PollSeconds
    }
    Write-Verbose ("{0}: TIMED OUT after {1}s." -f $Activity, $TimeoutSeconds)
    return $false
}

function Get-E8ControlRegister {
    <#
        The control register: the eight mitigation strategies, the collector that
        assesses each, and the baseline automatability expectation. Drives the
        orchestrator and documents coverage for the evidence pack.
    #>
    [CmdletBinding()]
    param()
    return @(
        [pscustomobject]@{ ControlId='E8-ML1-MFA';      Order=1; Strategy='Multi-factor authentication';     Collector='Get-E8MfaCoverage';             Expected='Automated' }
        [pscustomobject]@{ ControlId='E8-ML1-ADMIN';    Order=2; Strategy='Restrict administrative privileges'; Collector='Get-E8RestrictAdminPrivileges'; Expected='PartiallyAutomated' }
        [pscustomobject]@{ ControlId='E8-ML1-PATCHAPP'; Order=3; Strategy='Patch applications';                Collector='Get-E8PatchApplications';       Expected='PartiallyAutomated' }
        [pscustomobject]@{ ControlId='E8-ML1-PATCHOS';  Order=4; Strategy='Patch operating systems';           Collector='Get-E8PatchOperatingSystems';   Expected='PartiallyAutomated' }
        [pscustomobject]@{ ControlId='E8-ML1-MACROS';   Order=5; Strategy='Configure Microsoft Office macro settings'; Collector='Get-E8OfficeMacros';    Expected='PartiallyAutomated' }
        [pscustomobject]@{ ControlId='E8-ML1-HARDEN';   Order=6; Strategy='User application hardening';         Collector='Get-E8UserApplicationHardening'; Expected='PartiallyAutomated' }
        [pscustomobject]@{ ControlId='E8-ML1-APPCTRL';  Order=7; Strategy='Application control';                Collector='Get-E8ApplicationControl';      Expected='AttestationOnly' }
        [pscustomobject]@{ ControlId='E8-ML1-BACKUP';   Order=8; Strategy='Regular backups';                   Collector='Get-E8Backups';                 Expected='AttestationOnly' }
    )
}

Export-ModuleMember -Function `
    Get-E8Config, Get-E8ScopeList, Get-E8ReadOnlyScopeList, Get-E8NowUtc, New-E8Verdict, `
    Assert-E8Tenant, Get-E8SecurityDefaultsState, Get-E8LicenseContext, `
    Get-E8AssessablePopulation, Resolve-E8CaCoveredUserIds, Test-E8CaPolicyRequiresMfa, `
    New-E8SyntheticPassword, Get-E8ControlRegister, Wait-E8Condition
