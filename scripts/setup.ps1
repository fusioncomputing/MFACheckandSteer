[CmdletBinding()]
param()

Write-Host "=== MFA Check & Steer setup ===" -ForegroundColor Cyan
Write-Host "PowerShell version: $($PSVersionTable.PSVersion)"

if ([version]$PSVersionTable.PSVersion -lt [version]'7.4') {
    Write-Warning "PowerShell 7.4+ is recommended. Current version: $($PSVersionTable.PSVersion)"
}

$modules = @(
    @{ Name = 'Pester'; MinimumVersion = '5.5.0' },
    @{ Name = 'PSScriptAnalyzer'; MinimumVersion = '1.21.0' },
    @{ Name = 'Microsoft.Graph'; MinimumVersion = '2.12.0' }
)

foreach ($module in $modules) {
    $name = $module.Name
    $minVersion = [version]$module.MinimumVersion
    $installed = Get-Module -ListAvailable -Name $name | Sort-Object Version -Descending | Select-Object -First 1

    if ($installed -and [version]$installed.Version -ge $minVersion) {
        Write-Host "Module '$name' already installed (v$($installed.Version))."
        continue
    }

    Write-Host "Installing module '$name' (minimum $minVersion)..." -ForegroundColor Yellow
    try {
        Install-Module -Name $name -MinimumVersion $minVersion -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
        Write-Host "Module '$name' installed." -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to install module '$name': $_"
        throw
    }
}

Write-Host "Setup complete."
