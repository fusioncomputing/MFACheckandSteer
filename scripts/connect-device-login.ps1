[CmdletBinding()]
param(
    [string[]] $Scopes = @(
        'AuditLog.Read.All',
        'Policy.Read.All',
        'Directory.Read.All',
        'UserAuthenticationMethod.Read.All',
        'IdentityRiskyUser.Read.All'
    ),
    [switch] $SkipBetaProfile
)

$moduleManifest = Join-Path -Path $PSScriptRoot -ChildPath '..\src\MFACheckandSteer.psd1'

Write-Host "Step 1/4: Importing MFA Check & Steer module..." -ForegroundColor Cyan
if (-not (Test-Path $moduleManifest)) {
    throw "Module manifest not found at $moduleManifest"
}
Import-Module $moduleManifest -Force
Write-Host "Module imported successfully." -ForegroundColor Green

Write-Host "Step 2/4: Preparing device code authentication request." -ForegroundColor Cyan
Write-Host "Requested Microsoft Graph scopes:" -ForegroundColor Yellow
$Scopes | ForEach-Object { Write-Host "  - $_" -ForegroundColor Yellow }
if ($SkipBetaProfile) {
    Write-Host "Beta profile selection will be skipped as requested." -ForegroundColor Yellow
}
else {
    Write-Host "Beta profile will be selected after login (required for enriched sign-in details)." -ForegroundColor Yellow
}

Write-Host "Step 3/4: Prompting Global Administrator to complete device login..." -ForegroundColor Cyan
Write-Host "Follow the instructions in the console and browser to sign in. Cached credentials will be stored for reuse." -ForegroundColor Magenta

$connectParams = @{
    Scopes = $Scopes
}
if ($SkipBetaProfile) {
    $connectParams['SkipBetaProfile'] = $true
}
if ($PSBoundParameters.ContainsKey('Verbose')) {
    $connectParams['Verbose'] = $true
}

$context = Connect-MfaGraphDeviceCode @connectParams

Write-Host "Step 4/4: Verifying Graph context..." -ForegroundColor Cyan

$tenantId = $null
$account = $null
try {
    if ($context -and $context.TenantId) {
        $tenantId = $context.TenantId
    }
    elseif ($context.Tenant -and $context.Tenant.Id) {
        $tenantId = $context.Tenant.Id
    }
}
catch {
    # swallow lookup issues
}

try {
    if ($context -and $context.Account -and $context.Account.Username) {
        $account = $context.Account.Username
    }
    elseif ($context -and $context.Account) {
        $account = $context.Account
    }
}
catch {
}

if ($tenantId) {
    Write-Host "Connected tenant: $tenantId" -ForegroundColor Green
}
if ($account) {
    Write-Host "Signed-in account: $account" -ForegroundColor Green
}

if ($context -and $context.Scopes) {
    Write-Host "Granted scopes:" -ForegroundColor Green
    $context.Scopes | Sort-Object | ForEach-Object { Write-Host "  - $_" -ForegroundColor Green }
}

Write-Host "Device login complete. You can now call Get-MfaEntraSignIn or Get-MfaEntraRegistration without re-authenticating." -ForegroundColor Cyan
