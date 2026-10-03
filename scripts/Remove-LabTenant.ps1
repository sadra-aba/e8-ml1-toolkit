<#
    Remove-LabTenant.ps1
    Tear down synthetic lab objects: lab Conditional Access policies, synthetic
    users (e8labNN) and the synthetic group. Guarded by ShouldProcess; NEVER
    touches the break-glass account or any non-synthetic object.

    Example:
      .\Remove-LabTenant.ps1 -WhatIf        # preview
      .\Remove-LabTenant.ps1 -Confirm:$false
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [string] $ConfigPath
)

$ErrorActionPreference = 'Stop'

$common = [IO.Path]::Combine($PSScriptRoot, '..', 'src', 'Common', 'E8Toolkit.psm1')
Import-Module $common -Force
Import-Module Microsoft.Graph.Users          -ErrorAction SilentlyContinue
Import-Module Microsoft.Graph.Groups         -ErrorAction SilentlyContinue
Import-Module Microsoft.Graph.Identity.SignIns -ErrorAction SilentlyContinue

$cfg = Get-E8Config -Path $ConfigPath
[void](Assert-E8Tenant -Config $cfg)

$domain    = $cfg.tenant.primaryDomain
$prefix    = $cfg.lab.syntheticUserPrefix
$count     = [int]$cfg.lab.syntheticUserCount
$groupName = $cfg.lab.syntheticGroupName
$polPrefix = $cfg.lab.labPolicyPrefix
$bgUpn     = $cfg.breakGlass.userPrincipalName

# --- lab CA policies ---
try {
    $pols = @(Get-MgIdentityConditionalAccessPolicy -All -ErrorAction Stop |
              Where-Object { ("$($_.DisplayName)").StartsWith($polPrefix) })
    foreach ($p in $pols) {
        if ($PSCmdlet.ShouldProcess($p.DisplayName, 'Remove lab Conditional Access policy')) {
            Remove-MgIdentityConditionalAccessPolicy -ConditionalAccessPolicyId $p.Id
            Write-Host "Removed policy '$($p.DisplayName)'"
        }
    }
} catch { Write-Warning "Policy cleanup: $($_.Exception.Message)" }

# --- synthetic users (never the break-glass account) ---
for ($i = 1; $i -le $count; $i++) {
    $upn = ('{0}{1:D2}@{2}' -f $prefix, $i, $domain)
    if ($upn -eq $bgUpn) { continue }
    $u = Get-MgUser -Filter "userPrincipalName eq '$upn'" -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($u -and $PSCmdlet.ShouldProcess($upn, 'Remove synthetic user')) {
        Remove-MgUser -UserId $u.Id
        Write-Host "Removed user $upn"
    }
}

# --- synthetic group ---
$g = Get-MgGroup -Filter "displayName eq '$groupName'" -ErrorAction SilentlyContinue | Select-Object -First 1
if ($g -and $PSCmdlet.ShouldProcess($groupName, 'Remove synthetic group')) {
    Remove-MgGroup -GroupId $g.Id
    Write-Host "Removed group '$groupName'"
}

Write-Host "Teardown complete."
