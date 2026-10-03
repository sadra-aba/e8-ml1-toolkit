<#
    Connect-E8Lab.ps1
    Authenticate to Microsoft Graph and run pre-flight safety checks.

    Two auth modes:
      Delegated  (default) : interactive sign-in, least-privilege scopes.
      AppOnly              : unattended (certificate thumbprint preferred, or a
                             client secret from an environment variable). Used by
                             the scheduled/unattended runner.

    After connecting it ALWAYS:
      1. verifies the signed-in tenant matches config (Assert-E8Tenant),
      2. reports Security Defaults state (blocks Conditional Access when on),
      3. confirms the break-glass account resolves.

    No credential, token or secret is ever written to disk or to output (T8).
#>
[CmdletBinding()]
param(
    [string] $ConfigPath,
    [ValidateSet('Delegated','AppOnly')]
    [string] $Mode,
    [switch] $Quiet
)

$ErrorActionPreference = 'Stop'

# --- load shared module ---
$common = [IO.Path]::Combine($PSScriptRoot, '..', 'src', 'Common', 'E8Toolkit.psm1')
Import-Module $common -Force

$cfg = Get-E8Config -Path $ConfigPath
if (-not $Mode) { $Mode = $cfg.auth.mode }

# --- ensure Graph SDK is present ---
if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
    throw "E8: Microsoft.Graph PowerShell SDK not found. Install-Module Microsoft.Graph -Scope CurrentUser."
}
Import-Module Microsoft.Graph.Authentication -ErrorAction Stop

# --- connect ---
if ($Mode -eq 'AppOnly') {
    $clientId = $cfg.auth.appOnly.clientId
    $tenantId = $cfg.tenant.tenantId
    $thumb    = $cfg.auth.appOnly.certificateThumbprint
    if ($thumb) {
        if (-not $Quiet) { Write-Host "E8: connecting app-only (certificate) as $clientId ..." }
        Connect-MgGraph -TenantId $tenantId -ClientId $clientId -CertificateThumbprint $thumb -NoWelcome -ErrorAction Stop
    } else {
        $secretVar = $cfg.auth.appOnly.clientSecretEnvVar
        $secret = [Environment]::GetEnvironmentVariable($secretVar)
        if (-not $secret) {
            throw ("E8: app-only mode needs a certificate thumbprint OR the client secret " +
                   "in environment variable '$secretVar' (neither found).")
        }
        if (-not $Quiet) { Write-Host "E8: connecting app-only (client secret) as $clientId ..." }
        $sec = ConvertTo-SecureString $secret -AsPlainText -Force
        $cred = New-Object System.Management.Automation.PSCredential($clientId, $sec)
        Connect-MgGraph -TenantId $tenantId -ClientSecretCredential $cred -NoWelcome -ErrorAction Stop
        $secret = $null; $sec = $null; $cred = $null   # drop the secret from memory promptly
    }
} else {
    $scopes = Get-E8ScopeList
    if (-not $Quiet) { Write-Host "E8: connecting delegated with $($scopes.Count) least-privilege scopes ..." }
    Connect-MgGraph -Scopes $scopes -NoWelcome -ErrorAction Stop
}

# --- pre-flight safety checks ---
[void](Assert-E8Tenant -Config $cfg)

$sd = Get-E8SecurityDefaultsState
$lic = Get-E8LicenseContext

if (-not $Quiet) {
    Write-Host ""
    Write-Host "E8 pre-flight ----------------------------------------"
    Write-Host ("  Tenant           : {0}" -f $cfg.tenant.primaryDomain)
    Write-Host ("  Detected tier    : {0}" -f $lic.detectedTier)
    Write-Host ("  Conditional Acc. : {0}" -f $lic.conditionalAccess)
    Write-Host ("  Intune           : {0}" -f $lic.intune)
    Write-Host ("  Defender for Biz : {0}" -f $lic.defenderForBusiness)
    if ($null -eq $sd) {
        Write-Host "  Security Defaults: UNKNOWN (could not read policy)"
    } elseif ($sd) {
        Write-Host "  Security Defaults: ENABLED  (Conditional Access cannot be used while on)"
    } else {
        Write-Host "  Security Defaults: disabled (Conditional Access available)"
    }
    Write-Host ("  Break-glass      : {0}" -f $cfg.breakGlass.userPrincipalName)
    Write-Host "------------------------------------------------------"
    Write-Host ""
}

# Return a context object the callers can reuse.
return [pscustomobject][ordered]@{
    Config           = $cfg
    Mode             = $Mode
    SecurityDefaults = $sd
    License          = $lic
    ConnectedUtc     = (Get-E8NowUtc)
}
