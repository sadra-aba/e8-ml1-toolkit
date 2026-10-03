<#
    Run-Live.ps1
    One-shot live run: device-code sign-in, auto-fill config from the signed-in
    account, then the full assessment. Designed to be launched with:

        powershell -NoProfile -ExecutionPolicy Bypass -File C:\E8-Toolkit\Run-Live.ps1

    Single sign-in (Connect-E8Lab reuses this session), single device code, no
    multi-line paste. Config is only written if sign-in actually succeeds.
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
Set-Location $root

Import-Module ([IO.Path]::Combine($root,'src','Common','E8Toolkit.psm1')) -Force
Import-Module Microsoft.Graph.Authentication -ErrorAction Stop

Write-Host ""
Write-Host "==================================================================="
Write-Host " E8 live run - a device code will appear below."
Write-Host " Open https://login.microsoft.com/device, enter the code, sign in as"
Write-Host " your Global Admin, and consent. Then this will continue on its own."
Write-Host "==================================================================="
Write-Host ""

Connect-MgGraph -Scopes (Get-E8ScopeList) -NoWelcome -UseDeviceAuthentication

$ctx = Get-MgContext
if (-not $ctx -or -not $ctx.Account) {
    throw "Sign-in did not complete (no Graph context). Nothing was changed. Re-run and finish the device-code sign-in."
}
Write-Host ""
Write-Host ("Signed in as: {0}   tenant: {1}" -f $ctx.Account, $ctx.TenantId)

# auto-fill config from the signed-in session (break-glass = signed-in account)
$cfgPath = [IO.Path]::Combine($root,'config','lab.config.json')
$j = Get-Content $cfgPath -Raw | ConvertFrom-Json
$j.tenant.tenantId = "$($ctx.TenantId)"
$j.breakGlass.userPrincipalName = "$($ctx.Account)"
($j | ConvertTo-Json -Depth 12) | Set-Content -LiteralPath $cfgPath -Encoding UTF8
Write-Host ("Config set: break-glass = {0}" -f $ctx.Account)
Write-Host "-------------------------------------------------------------------"

# run the assessment; Connect-E8Lab will reuse this same session (no 2nd sign-in)
& ([IO.Path]::Combine($root,'Invoke-E8Assessment.ps1'))

Write-Host ""
Write-Host "Done. Artefacts are in: $([IO.Path]::Combine($root,'output'))"
