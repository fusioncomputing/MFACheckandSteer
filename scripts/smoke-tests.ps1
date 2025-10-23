[CmdletBinding()]
param()

$modulePath = Join-Path -Path $PSScriptRoot -ChildPath '..\src\MFACheckandSteer.psd1'

if (-not (Test-Path $modulePath)) {
    throw "Module manifest not found at $modulePath"
}

Import-Module $modulePath -Force

$status = Get-MfaEnvironmentStatus
$status | Format-Table -AutoSize

if (-not (Test-MfaGraphPrerequisite)) {
    throw "Microsoft.Graph module is missing. Run scripts/setup.ps1."
}

Write-Host "Smoke tests passed." -ForegroundColor Green
