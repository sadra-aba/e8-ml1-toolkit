<#
    Register-E8ScheduledTask.ps1
    Register a Windows Scheduled Task that runs the UNATTENDED (app-only)
    assessment on a schedule and files the evidence pack under output/.

    App-only auth (certificate thumbprint in lab.config.json) is strongly preferred
    for unattended runs so no interactive sign-in or stored secret is needed.

    Example:
      .\Register-E8ScheduledTask.ps1 -Time 02:00 -TaskName "E8 Weekly Assessment"
#>
[CmdletBinding()]
param(
    [string] $TaskName = 'E8 ML1 Assessment',
    [string] $Time = '02:00',
    [ValidateSet('Daily','Weekly')] [string] $Frequency = 'Weekly',
    [string] $DayOfWeek = 'Monday',
    [string] $ConfigPath
)

$ErrorActionPreference = 'Stop'

$root   = Split-Path -Parent $PSScriptRoot
$runner = [IO.Path]::Combine($root, 'Invoke-E8Assessment.ps1')
if (-not (Test-Path -LiteralPath $runner)) { throw "Runner not found: $runner" }

$psExe = (Get-Command powershell.exe -ErrorAction SilentlyContinue).Source
if (-not $psExe) { $psExe = 'powershell.exe' }

$argLine = "-NoProfile -ExecutionPolicy Bypass -File `"$runner`" -Mode AppOnly -Quiet"
if ($ConfigPath) { $argLine += " -ConfigPath `"$ConfigPath`"" }

$action  = New-ScheduledTaskAction -Execute $psExe -Argument $argLine -WorkingDirectory $root

if ($Frequency -eq 'Daily') {
    $trigger = New-ScheduledTaskTrigger -Daily -At $Time
} else {
    $trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek $DayOfWeek -At $Time
}

$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -DontStopOnIdleEnd `
    -ExecutionTimeLimit (New-TimeSpan -Minutes 30)

Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger `
    -Settings $settings -Description 'Essential Eight ML1 automated assessment + evidence pack' -Force | Out-Null

Write-Host "Registered scheduled task '$TaskName' ($Frequency $Time)."
Write-Host "It runs: $psExe $argLine"
Write-Host "NOTE: app-only auth requires a certificate thumbprint (preferred) or the client-secret env var in lab.config.json."
