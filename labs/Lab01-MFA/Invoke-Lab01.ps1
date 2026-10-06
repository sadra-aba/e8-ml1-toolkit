<#
    Invoke-Lab01.ps1    Multi-factor authentication (Essential Eight ML1)
    The four-stage validation cycle: WEAKEN -> ASSESS -> REMEDIATE -> RE-ASSESS.

    *** THIS SCRIPT DELIBERATELY WEAKENS SECURITY CONTROLS IN THE TENANT. ***
    It is intended ONLY for the isolated lab tenant. It refuses to run unless:
      * -ConfirmWeaken is supplied (or you answer the confirmation prompt),
      * the signed-in tenant matches config (Assert-E8Tenant),
      * the break-glass account resolves,
      * Security Defaults is OFF (Conditional Access is required for this lab).

    Produces: lab01-mfa-before.json, lab01-mfa-after.json, lab01-mfa-result.json,
    and an evidence pack with the before/after transition.

    Propagation is handled by polling (Wait-E8Condition), not a fixed sleep.
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [string] $ConfigPath,
    [switch] $ConfirmWeaken,
    [switch] $SkipSeed,
    [int]    $PropagationTimeoutSeconds = 180
)

$ErrorActionPreference = 'Stop'

$root       = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$common     = [IO.Path]::Combine($root, 'src', 'Common', 'E8Toolkit.psm1')
$connect    = [IO.Path]::Combine($root, 'scripts', 'Connect-E8Lab.ps1')
$seed       = [IO.Path]::Combine($root, 'scripts', 'Initialize-LabTenant.ps1')
$mfaScript  = [IO.Path]::Combine($root, 'src', 'Collectors', 'Get-E8MfaCoverage.ps1')
$packScript = [IO.Path]::Combine($root, 'src', 'Evidence', 'New-EvidencePack.ps1')

Import-Module $common -Force
Import-Module Microsoft.Graph.Identity.SignIns -ErrorAction SilentlyContinue

# --- connect + safety ---
$connectArgs = @{}
if ($ConfigPath) { $connectArgs['ConfigPath'] = $ConfigPath }
$ctx = & $connect @connectArgs
$cfg = $ctx.Config

if ($ctx.SecurityDefaults -eq $true) {
    throw ("E8 Lab 01 requires Security Defaults to be DISABLED (it blocks Conditional Access). " +
           "Disable Security Defaults in the lab tenant and retry.")
}

# --- destructive-action gate ---
if (-not $ConfirmWeaken) {
    if (-not $PSCmdlet.ShouldProcess($cfg.tenant.primaryDomain,
        'DELIBERATELY WEAKEN MFA (remove enforcing Conditional Access policy) then remediate')) {
        throw "Aborted: Lab 01 weakens security controls. Re-run with -ConfirmWeaken to proceed."
    }
}

# --- break-glass ---
$pop = Get-E8AssessablePopulation -Config $cfg
$bg  = $pop.BreakGlass
Write-Host ("Break-glass account resolved: {0} ({1})" -f $bg.UserPrincipalName, $bg.Id)

# --- optional seeding ---
if (-not $SkipSeed) {
    Write-Host "Seeding synthetic lab objects ..."
    & $seed -ConfigPath $ConfigPath | Out-Null
}

$prefix  = $cfg.lab.labPolicyPrefix
$outDir  = $cfg.output.resolvedDirectory
if (-not (Test-Path -LiteralPath $outDir)) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }

function Get-LabEnforcingPolicies {
    $all = @(Get-MgIdentityConditionalAccessPolicy -All -ErrorAction Stop)
    return @($all | Where-Object {
        ("$($_.DisplayName)").StartsWith($prefix) -and (Test-E8CaPolicyRequiresMfa -Policy $_)
    })
}

# ========================= STAGE 1: WEAKEN =========================
Write-Host ""
Write-Host "[1/4] WEAKEN  removing any enforcing lab MFA policy ..."
$existing = Get-LabEnforcingPolicies
foreach ($p in $existing) {
    Write-Host ("   removing policy '{0}' ({1})" -f $p.DisplayName, $p.Id)
    Remove-MgIdentityConditionalAccessPolicy -ConditionalAccessPolicyId $p.Id -ErrorAction Stop
}
# Poll on the MEASURED coverage (same read path as the verdict), not the policy
# list, to defeat directory replication lag across Graph replicas.
$gone = Wait-E8Condition -Activity 'Weaken propagation (coverage 0)' -TimeoutSeconds $PropagationTimeoutSeconds -PollSeconds 10 -Condition {
    (& $mfaScript -Config $cfg -SecurityDefaultsEnabled $false).coverage.coveragePercent -eq 0
}
if (-not $gone) { Write-Warning "MFA coverage did not reach 0% within the timeout; recording the current state anyway." }

# ========================= STAGE 2: ASSESS (before) =========================
Write-Host "[2/4] ASSESS  measuring pre-remediation state ..."
$before = & $mfaScript -Config $cfg -SecurityDefaultsEnabled $false
$beforePath = [IO.Path]::Combine($outDir, 'lab01-mfa-before.json')
$before | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $beforePath -Encoding UTF8
Write-Host ("   before: {0} / {1}% coverage" -f $before.verdict, $before.coverage.coveragePercent)

# ========================= STAGE 3: REMEDIATE =========================
Write-Host "[3/4] REMEDIATE  creating MFA policy (break-glass excluded) ..."
$policyName = ($prefix + '01 Require MFA for all users')
$conditions = @{
    Applications = @{ IncludeApplications = @('All') }
    Users        = @{ IncludeUsers = @('All'); ExcludeUsers = @($bg.Id) }
    ClientAppTypes = @('all')
}
$grant = @{ Operator = 'OR'; BuiltInControls = @('mfa') }

$new = New-MgIdentityConditionalAccessPolicy -DisplayName $policyName -State 'enabled' `
    -Conditions $conditions -GrantControls $grant -ErrorAction Stop
Write-Host ("   created '{0}' ({1}); break-glass {2} excluded" -f $policyName, $new.Id, $bg.Id)

$active = Wait-E8Condition -Activity 'Remediation propagation (coverage 100)' -TimeoutSeconds $PropagationTimeoutSeconds -PollSeconds 10 -Condition {
    (& $mfaScript -Config $cfg -SecurityDefaultsEnabled $false).coverage.coveragePercent -ge 100
}
if (-not $active) { Write-Warning "MFA coverage did not reach 100% within the timeout; recording the current state anyway." }

# ========================= STAGE 4: RE-ASSESS (after) =========================
Write-Host "[4/4] RE-ASSESS  measuring post-remediation state (same collector) ..."
$after = & $mfaScript -Config $cfg -SecurityDefaultsEnabled $false
$afterPath = [IO.Path]::Combine($outDir, 'lab01-mfa-after.json')
$after | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $afterPath -Encoding UTF8
Write-Host ("   after: {0} / {1}% coverage" -f $after.verdict, $after.coverage.coveragePercent)

# ========================= RESULT + EVIDENCE =========================
$nowUtc = [DateTime]::UtcNow
$localStr = $nowUtc.ToString('u')
try {
    $tz = [System.TimeZoneInfo]::FindSystemTimeZoneById('AUS Eastern Standard Time')
    $localStr = [System.TimeZoneInfo]::ConvertTimeFromUtc($nowUtc, $tz).ToString('yyyy-MM-dd HH:mm:ss') + ' (Sydney)'
} catch {}
$account = ''
try { $account = (Get-MgContext).Account } catch {}

$run = [pscustomobject][ordered]@{
    meta = [ordered]@{
        studentName     = $cfg.operator.studentName
        studentId       = $cfg.operator.studentId
        tenantDomain    = $cfg.tenant.primaryDomain
        assessingAccount= $account
        collectedUtc    = $nowUtc.ToString('yyyy-MM-ddTHH:mm:ssZ')
        collectedLocal  = $localStr
        detectedTier    = $ctx.License.detectedTier
        securityDefaults= $ctx.SecurityDefaults
        toolkitVersion  = 'e8-ml1-toolkit/0.4'
        mode            = $ctx.Mode
        lab             = 'Lab01-MFA'
    }
    results    = @($after)
    transition = [ordered]@{ before = $before; after = $after }
}
$resultPath = [IO.Path]::Combine($outDir, 'lab01-mfa-result.json')
$run | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $resultPath -Encoding UTF8

$packPath = [IO.Path]::Combine($outDir, 'lab01-evidence-pack.html')
& $packScript -Run $run -OutputPath $packPath | Out-Null

Write-Host ""
Write-Host "Lab 01 complete -------------------------------------------"
Write-Host ("  Before : {0} ({1}%)" -f $before.verdict, $before.coverage.coveragePercent)
Write-Host ("  After  : {0} ({1}%)" -f $after.verdict, $after.coverage.coveragePercent)
Write-Host ("  JSON   : {0}" -f $resultPath)
Write-Host ("  Pack   : {0}" -f $packPath)
Write-Host "-----------------------------------------------------------"
return $run
