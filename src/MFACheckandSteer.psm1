function Get-MfaEnvironmentStatus {
    [CmdletBinding()]
    param()

    $modules = @(
        'Microsoft.Graph',
        'Pester',
        'PSScriptAnalyzer'
    )

    $status = foreach ($module in $modules) {
        $info = Get-Module -ListAvailable -Name $module | Sort-Object Version -Descending | Select-Object -First 1
        [pscustomobject]@{
            Module  = $module
            Found   = [bool]$info
            Version = if ($info) { $info.Version.ToString() } else { $null }
        }
    }

    return $status
}

function Test-MfaGraphPrerequisite {
    [CmdletBinding()]
    param()

    $graphModule = Get-Module -ListAvailable -Name Microsoft.Graph | Sort-Object Version -Descending | Select-Object -First 1
    if (-not $graphModule) {
        Write-Warning 'Microsoft.Graph module is not installed. Run scripts/setup.ps1.'
        return $false
    }

    return $true
}

function Get-MfaGraphContext {
    if (-not (Test-MfaGraphPrerequisite)) {
        return $null
    }

    $contextCommand = Get-Command -Name Get-MgContext -ErrorAction SilentlyContinue
    if (-not $contextCommand) {
        return $null
    }

    return & $contextCommand
}

function ConvertTo-MfaODataDateTime {
    param(
        [Parameter(Mandatory)]
        [datetime] $DateTime
    )

    return $DateTime.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
}

function Invoke-MfaGraphSignInQuery {
    param(
        [string] $Filter,
        [switch] $All,
        [int] $Top = 200
    )

    $params = @{
        ConsistencyLevel = 'eventual'
    }

    if ($All.IsPresent) {
        $params['All'] = $true
    }
    else {
        $params['Top'] = $Top
    }

    if ($Filter) {
        $params['Filter'] = $Filter
    }

    return Get-MgAuditLogSignIn @params
}

function Invoke-MfaGraphAuthenticationMethodQuery {
    param(
        [Parameter(Mandatory)]
        [string] $UserId
    )

    return Get-MgUserAuthenticationMethod -UserId $UserId -All
}

function Connect-MfaGraphDeviceCode {
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

    if (-not (Test-MfaGraphPrerequisite)) {
        throw "Microsoft.Graph module is not installed. Run scripts/setup.ps1 before attempting to connect."
    }

    Write-Verbose "Requesting Graph device code sign-in for scopes: $($Scopes -join ', ')"

    try {
        Connect-MgGraph -Scopes $Scopes -UseDeviceCode -NoWelcome | Out-Null
    }
    catch {
        throw "Connect-MgGraph using device code failed: $_"
    }

    if (-not $SkipBetaProfile.IsPresent) {
        $profileCommand = Get-Command -Name Select-MgProfile -ErrorAction SilentlyContinue
        if ($profileCommand) {
            try {
                Select-MgProfile -Name beta
            }
            catch {
                Write-Warning "Failed to select the beta profile: $_"
            }
        }
        else {
            Write-Warning "Select-MgProfile command not found. Install the Microsoft.Graph module bundle if beta profile selection is required."
        }
    }

    $context = Get-MfaGraphContext
    if (-not $context) {
        throw "Graph context was not established after device login."
    }

    return $context
}

function Get-MfaEntraSignIn {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [datetime] $StartTime,
        [Parameter(Mandatory)]
        [datetime] $EndTime,
        [string] $UserPrincipalName,
        [int] $Top = 200,
        [switch] $All
    )

    if ($EndTime -lt $StartTime) {
        throw "EndTime must be greater than or equal to StartTime."
    }

    $context = Get-MfaGraphContext
    if (-not $context) {
        throw "Microsoft Graph context not found. Run Connect-MgGraph before calling Get-MfaEntraSignIn."
    }

    $filterParts = @(
        "createdDateTime ge $(ConvertTo-MfaODataDateTime -DateTime $StartTime)",
        "createdDateTime le $(ConvertTo-MfaODataDateTime -DateTime $EndTime)"
    )

    if ($UserPrincipalName) {
        $escapedUpn = $UserPrincipalName.Replace("'", "''")
        $filterParts += "userPrincipalName eq '$escapedUpn'"
    }

    $filter = ($filterParts -join ' and ')
    return Invoke-MfaGraphSignInQuery -Filter $filter -All:$All.IsPresent -Top $Top
}

function Get-MfaEntraRegistration {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('UserPrincipalName')]
        [string] $UserId
    )
    process {
        $context = Get-MfaGraphContext
        if (-not $context) {
            throw "Microsoft Graph context not found. Run Connect-MgGraph before calling Get-MfaEntraRegistration."
        }

        Invoke-MfaGraphAuthenticationMethodQuery -UserId $UserId
    }
}

Export-ModuleMember -Function Get-MfaEnvironmentStatus, Test-MfaGraphPrerequisite, Get-MfaEntraSignIn, Get-MfaEntraRegistration, Connect-MfaGraphDeviceCode
