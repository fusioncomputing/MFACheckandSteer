[CmdletBinding()]
param(
    [ValidateRange(1, 720)]
    [int] $LookbackHours = 24,
    [string[]] $UserPrincipalName,
    [string[]] $RegistrationUserPrincipalName,
    [switch] $IncludePrivilegedRoleAudit,
    [string] $OutputDirectory,
    [switch] $SkipAuthorization,
    [switch] $OpenReport,
    [switch] $PassThru
)

$repoRoot = Resolve-Path (Join-Path -Path $PSScriptRoot -ChildPath '..')
$modulePath = Join-Path -Path $repoRoot -ChildPath 'src\MFACheckandSteer.psd1'

if (-not (Test-Path -Path $modulePath)) {
    throw "Module manifest not found at path '$modulePath'."
}

Import-Module $modulePath -Force

Write-Host ("MFA tenant report - lookback: {0} hour(s)" -f $LookbackHours) -ForegroundColor Cyan

$invokeParams = @{
    LookbackHours             = $LookbackHours
    OutputDirectory           = $OutputDirectory
    SkipAuthorization         = $SkipAuthorization
    OpenReport                = $OpenReport
}

if ($UserPrincipalName) {
    $invokeParams['UserPrincipalName'] = $UserPrincipalName
}

if ($RegistrationUserPrincipalName) {
    $invokeParams['RegistrationUserPrincipalName'] = $RegistrationUserPrincipalName
}

if ($IncludePrivilegedRoleAudit) {
    $invokeParams['IncludePrivilegedRoleAudit'] = $true
}

if ($PassThru) {
    $invokeParams['PassThru'] = $true
}

$result = Invoke-MfaTenantReport @invokeParams

if ($PassThru) {
    $result
}
else {
    Write-Host ("HTML report saved to: {0}" -f $result) -ForegroundColor Green
}
