<#
    Invoke-E8Assessment.ps1
    The safe default entry point. Connects, runs every collector in the control
    register (ASSESSMENT ONLY -- nothing here weakens or modifies the tenant), and
    writes a timestamped JSON result plus a self-contained HTML evidence pack.

    Weakening controls is deliberately NOT part of this script. The destructive
    weaken/remediate cycle lives separately in labs/Lab01-MFA/Invoke-Lab01.ps1 and
    must be invoked explicitly.

    Examples:
      .\Invoke-E8Assessment.ps1                      # delegated, interactive
      .\Invoke-E8Assessment.ps1 -Mode AppOnly        # unattended (scheduler)
      .\Invoke-E8Assessment.ps1 -ConfigPath C:\path\lab.config.json
#>
[CmdletBinding()]
param(
    [string] $ConfigPath,
    [ValidateSet('Delegated','AppOnly')] [string] $Mode,
    [switch] $NoEvidencePack,
    [switch] $Quiet
)

$ErrorActionPreference = 'Stop'
$ToolkitVersion = 'e8-ml1-toolkit/0.4'

# --- paths ---
$root       = $PSScriptRoot
$common     = [IO.Path]::Combine($root, 'src', 'Common', 'E8Toolkit.psm1')
$connect    = [IO.Path]::Combine($root, 'scripts', 'Connect-E8Lab.ps1')
$collectDir = [IO.Path]::Combine($root, 'src', 'Collectors')
$packScript = [IO.Path]::Combine($root, 'src', 'Evidence', 'New-EvidencePack.ps1')

Import-Module $common -Force

# --- connect + pre-flight ---
$connectArgs = @{ Quiet = $Quiet.IsPresent }
if ($ConfigPath) { $connectArgs['ConfigPath'] = $ConfigPath }
if ($Mode)       { $connectArgs['Mode'] = $Mode }
$ctx = & $connect @connectArgs

$cfg = $ctx.Config
$lic = $ctx.License
$sd  = $ctx.SecurityDefaults

# --- shared call context; each collector gets only the params it declares ---
$callCtx = @{
    Config                  = $cfg
    License                 = $lic
    SecurityDefaultsEnabled = $sd
}

$register = Get-E8ControlRegister | Sort-Object Order
$results  = @()

foreach ($entry in $register) {
    $path = [IO.Path]::Combine($collectDir, ($entry.Collector + '.ps1'))
    if (-not (Test-Path -LiteralPath $path)) {
        if (-not $Quiet) { Write-Warning "Collector missing: $($entry.Collector)" }
        continue
    }
    if (-not $Quiet) { Write-Host ("  [{0}] {1} ..." -f $entry.Order, $entry.Strategy) }
    $cmd = Get-Command -Name $path -ErrorAction Stop
    $splat = @{}
    foreach ($k in $callCtx.Keys) { if ($cmd.Parameters.ContainsKey($k)) { $splat[$k] = $callCtx[$k] } }
    try {
        $results += (& $path @splat)
    } catch {
        if (-not $Quiet) { Write-Warning ("    collector '{0}' failed: {1}" -f $entry.Collector, $_.Exception.Message) }
        $results += (New-E8Verdict -ControlId $entry.ControlId -Strategy $entry.Strategy `
            -Verdict 'NotAssessed' -Automatability $entry.Expected -AssessmentMode 'Error' `
            -TenantDomain $cfg.tenant.primaryDomain `
            -VerdictReason ("Collector failed to run: {0}" -f $_.Exception.Message))
    }
}

# --- metadata ---
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
        detectedTier    = $lic.detectedTier
        securityDefaults= $sd
        toolkitVersion  = $ToolkitVersion
        mode            = $ctx.Mode
    }
    results = @($results)
}

# --- write artefacts ---
$outDir = $cfg.output.resolvedDirectory
if (-not (Test-Path -LiteralPath $outDir)) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }
$stamp   = $nowUtc.ToString('yyyyMMdd-HHmmss')
$jsonOut = [IO.Path]::Combine($outDir, "assessment-$stamp.json")
$run | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $jsonOut -Encoding UTF8
if (-not $Quiet) { Write-Host ""; Write-Host "JSON result : $jsonOut" }

if (-not $NoEvidencePack) {
    $htmlOut = [IO.Path]::Combine($outDir, "evidence-pack-$stamp.html")
    & $packScript -Run $run -OutputPath $htmlOut | Out-Null
    if (-not $Quiet) { Write-Host "Evidence pack: $htmlOut" }
}

# --- console summary ---
if (-not $Quiet) {
    Write-Host ""
    Write-Host "Result summary ---------------------------------------"
    foreach ($r in $run.results) {
        Write-Host ("  {0,-45} {1}" -f $r.strategy, $r.verdict)
    }
    Write-Host "------------------------------------------------------"
}

return $run
