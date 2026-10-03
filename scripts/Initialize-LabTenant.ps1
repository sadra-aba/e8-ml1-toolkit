<#
    Initialize-LabTenant.ps1
    Seed synthetic lab objects, idempotently: one security group and N synthetic
    member users (e8labNN). Safe to re-run — existing objects are reused, not
    duplicated. Passwords are generated in memory and never written anywhere (T8).

    This script WRITES to the tenant. It only creates clearly-synthetic objects
    (department "E8 Lab (synthetic)") and never touches real accounts.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string] $ConfigPath
)

$ErrorActionPreference = 'Stop'

$common = [IO.Path]::Combine($PSScriptRoot, '..', 'src', 'Common', 'E8Toolkit.psm1')
Import-Module $common -Force
Import-Module Microsoft.Graph.Users  -ErrorAction SilentlyContinue
Import-Module Microsoft.Graph.Groups -ErrorAction SilentlyContinue

$cfg = Get-E8Config -Path $ConfigPath
[void](Assert-E8Tenant -Config $cfg)   # safety: right tenant only

$domain     = $cfg.tenant.primaryDomain
$prefix     = $cfg.lab.syntheticUserPrefix
$count      = [int]$cfg.lab.syntheticUserCount
$groupName  = $cfg.lab.syntheticGroupName
$deptTag    = 'E8 Lab (synthetic)'

# --- group (idempotent) ---
$group = Get-MgGroup -Filter "displayName eq '$groupName'" -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $group) {
    if ($PSCmdlet.ShouldProcess($groupName, 'Create synthetic security group')) {
        $mailNick = ($groupName -replace '[^a-zA-Z0-9]', '').ToLower()
        $group = New-MgGroup -DisplayName $groupName -MailEnabled:$false -MailNickname $mailNick `
            -SecurityEnabled:$true -Description $deptTag
        Write-Host "Created group '$groupName' ($($group.Id))."
    }
} else {
    Write-Host "Group '$groupName' already exists ($($group.Id))."
}

# --- users (idempotent) ---
$created = 0; $existing = 0
for ($i = 1; $i -le $count; $i++) {
    $uname = ('{0}{1:D2}' -f $prefix, $i)
    $upn   = ('{0}@{1}' -f $uname, $domain)
    $user  = Get-MgUser -Filter "userPrincipalName eq '$upn'" -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $user) {
        if ($PSCmdlet.ShouldProcess($upn, 'Create synthetic user')) {
            $pwProfile = @{ Password = (New-E8SyntheticPassword); ForceChangePasswordNextSignIn = $false }
            $user = New-MgUser -AccountEnabled:$true -DisplayName ("E8 Lab User {0:D2}" -f $i) `
                -UserPrincipalName $upn -MailNickname $uname -Department $deptTag `
                -PasswordProfile $pwProfile -UsageLocation 'AU'
            $created++
            Write-Host "Created user $upn"
        }
    } else {
        $existing++
    }
    # ensure group membership (idempotent)
    if ($group -and $user) {
        $isMember = $false
        try {
            $members = Get-MgGroupMember -GroupId $group.Id -All -ErrorAction Stop
            $isMember = @($members | Where-Object { $_.Id -eq $user.Id }).Count -gt 0
        } catch {}
        if (-not $isMember -and $PSCmdlet.ShouldProcess($upn, "Add to group '$groupName'")) {
            New-MgGroupMember -GroupId $group.Id -DirectoryObjectId $user.Id
        }
    }
}

Write-Host ""
Write-Host ("Seeding complete: {0} created, {1} already existed, group '{2}' ready." -f $created, $existing, $groupName)
return [pscustomobject]@{ GroupId = $group.Id; Created = $created; Existing = $existing }
