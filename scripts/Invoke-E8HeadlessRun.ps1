<#
    Invoke-E8HeadlessRun.ps1
    Device-code sign-in + run, for hosts where Connect-MgGraph's interactive/WAM or
    its built-in device-code prompt cannot run (no console window handle, no
    listener). Does the OAuth device-code flow over plain HTTP, writes the user code
    to a file, polls for the token (tolerant of transient network blips), hands the
    token to the Graph SDK, auto-fills a per-tenant config from the signed-in
    account, then runs either the full assessment or the Lab 01 cycle.

    ASCII only on purpose: non-ASCII chars get mangled when Windows PowerShell 5.1
    reads a BOM-less script as ANSI.

    Examples:
      .\scripts\Invoke-E8HeadlessRun.ps1 -PrimaryDomain contoso.onmicrosoft.com
      .\scripts\Invoke-E8HeadlessRun.ps1 -PrimaryDomain contoso.onmicrosoft.com -Mode Lab01 -Label standard
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $PrimaryDomain,
    [ValidateSet('Assess','Lab01')] [string] $Mode = 'Assess',
    [string] $Label = 'run',
    [string] $ClientId = '14d82eec-204b-4c2f-b7e8-296a70dab67e'   # Microsoft Graph Command Line Tools
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
Import-Module ([IO.Path]::Combine($root,'src','Common','E8Toolkit.psm1')) -Force
Import-Module Microsoft.Graph.Authentication -ErrorAction Stop

$outDir = [IO.Path]::Combine($root,'output')
if (-not (Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }
$codeFile = [IO.Path]::Combine($outDir, '.devicecode.txt')
if (Test-Path $codeFile) { Remove-Item $codeFile -Force }

$scope = ((Get-E8ScopeList | ForEach-Object { "https://graph.microsoft.com/$_" }) -join ' ') + ' offline_access'

# --- device code ---
$dc = Invoke-RestMethod -Method POST `
    -Uri "https://login.microsoftonline.com/$PrimaryDomain/oauth2/v2.0/devicecode" `
    -Body @{ client_id = $ClientId; scope = $scope }
Set-Content -LiteralPath $codeFile -Value $dc.message -Encoding UTF8
Write-Host "DEVICE CODE ISSUED:"; Write-Host $dc.message

# --- poll for token (tolerant of transient network errors) ---
$interval = [int]$dc.interval; if ($interval -lt 5) { $interval = 5 }
$deadline = (Get-Date).AddSeconds([int]$dc.expires_in)
$tok = $null
while ((Get-Date) -lt $deadline) {
    Start-Sleep -Seconds $interval
    try {
        $tok = Invoke-RestMethod -Method POST `
            -Uri "https://login.microsoftonline.com/$PrimaryDomain/oauth2/v2.0/token" `
            -Body @{ grant_type='urn:ietf:params:oauth:grant-type:device_code'; client_id=$ClientId; device_code=$dc.device_code }
        break
    } catch {
        $msg = $_.ErrorDetails.Message; $e = $null; if ($msg) { try { $e = $msg | ConvertFrom-Json } catch {} }
        if ($e -and ($e.error -eq 'authorization_pending' -or $e.error -eq 'slow_down')) {
            if ($e.error -eq 'slow_down') { $interval += 5 }; continue
        }
        if ($e -and $e.error) { throw ("Device auth failed: " + $e.error_description) }
        Write-Host ("transient poll error, retrying: " + $_.Exception.Message); continue
    }
}
if (-not $tok) { throw "Device code expired before sign-in completed." }

Connect-MgGraph -AccessToken (ConvertTo-SecureString $tok.access_token -AsPlainText -Force) -NoWelcome
$ctx = Get-MgContext
if (-not $ctx -or -not $ctx.Account) { throw "No Graph context after token sign-in." }
Write-Host ("SIGNED-IN-AS: {0}  TENANT: {1}" -f $ctx.Account, $ctx.TenantId)

# --- per-tenant config (from the example template; never overwrites another run's) ---
$examplePath = [IO.Path]::Combine($root,'config','lab.config.example.json')
$cfgPath     = [IO.Path]::Combine($root,'config',("lab.config.{0}.json" -f $Label))
$j = Get-Content $examplePath -Raw | ConvertFrom-Json
$j.tenant.primaryDomain          = $PrimaryDomain
$j.tenant.tenantId               = "$($ctx.TenantId)"
$j.breakGlass.userPrincipalName  = "$($ctx.Account)"
($j | ConvertTo-Json -Depth 12) | Set-Content -LiteralPath $cfgPath -Encoding UTF8
Write-Host ("CONFIG: {0} (break-glass {1})" -f $cfgPath, $ctx.Account)
Write-Host "-------------------------------------------------------------"

# --- run ---
if ($Mode -eq 'Lab01') {
    & ([IO.Path]::Combine($root,'labs','Lab01-MFA','Invoke-Lab01.ps1')) -ConfigPath $cfgPath -ConfirmWeaken -SkipSeed
} else {
    & ([IO.Path]::Combine($root,'Invoke-E8Assessment.ps1')) -ConfigPath $cfgPath
}
Remove-Item $codeFile -Force -ErrorAction SilentlyContinue
Write-Host "HEADLESS-RUN-COMPLETE"
