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

function Test-MfaGraphThrottleError {
    param(
        [Parameter(Mandatory)]
        [System.Management.Automation.ErrorRecord] $ErrorRecord
    )

    if (-not $ErrorRecord) {
        return $false
    }

    $exception = $ErrorRecord.Exception
    if (-not $exception) {
        return $false
    }

    $statusProperties = @('ResponseStatusCode', 'StatusCode', 'ResponseCode')
    foreach ($prop in $statusProperties) {
        if ($exception.PSObject.Properties.Name -contains $prop) {
            $value = $exception.PSObject.Properties[$prop].Value
            if ($value -eq 429) {
                return $true
            }
        }
    }

    $message = $exception.Message
    if ($message -match '429' -or $message -match 'Too\s+Many\s+Requests' -or $message -match 'throttl') {
        return $true
    }

    if ($ErrorRecord.FullyQualifiedErrorId -match 'TooManyRequests') {
        return $true
    }

    return $false
}

function Invoke-MfaGraphWithRetry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [scriptblock] $Operation,
        [int] $MaxRetries = 3,
        [int] $InitialDelaySeconds = 1
    )

    $delay = [Math]::Max(1, $InitialDelaySeconds)

    for ($attempt = 0; $attempt -le $MaxRetries; $attempt++) {
        try {
            return & $Operation
        }
        catch {
            $errorRecord = $_
            $shouldRetry = Test-MfaGraphThrottleError -ErrorRecord $errorRecord
            if (-not $shouldRetry -or $attempt -eq $MaxRetries) {
                throw
            }

            Write-Warning ("Microsoft Graph throttled request (attempt {0}/{1}). Retrying in {2} second(s)..." -f ($attempt + 1), ($MaxRetries + 1), $delay)
            Start-Sleep -Seconds $delay
            $delay = [Math]::Min($delay * 2, 60)
        }
    }
}

function Invoke-MfaGraphSignInQuery {
    param(
        [string] $Filter,
        [switch] $All,
        [int] $Top = 200,
        [int] $MaxRetries = 3
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

    return Invoke-MfaGraphWithRetry -MaxRetries $MaxRetries -Operation {
        Get-MgAuditLogSignIn @params
    }
}

function Invoke-MfaGraphAuthenticationMethodQuery {
    param(
        [Parameter(Mandatory)]
        [string] $UserId,
        [int] $MaxRetries = 3
    )

    return Invoke-MfaGraphWithRetry -MaxRetries $MaxRetries -Operation {
        Get-MgUserAuthenticationMethod -UserId $UserId -All
    }
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

function Get-MfaDynamicPropertyValue {
    param(
        [Parameter(Mandatory)]
        [object] $InputObject,
        [Parameter(Mandatory)]
        [string] $PropertyName
    )

    if ($null -eq $InputObject) {
        return $null
    }

    $property = $InputObject.PSObject.Properties.Match($PropertyName)
    if ($property) {
        return $property.Value
    }

    $lowerName = ($PropertyName.Substring(0,1).ToLower() + $PropertyName.Substring(1))
    $lowerProperty = $InputObject.PSObject.Properties.Match($lowerName)
    if ($lowerProperty) {
        return $lowerProperty.Value
    }

    $dictionaryNames = @(
        $PropertyName,
        $lowerName,
        $PropertyName.ToLower(),
        $PropertyName.ToUpper()
    )

    if ($InputObject -is [System.Collections.IDictionary]) {
        foreach ($name in $dictionaryNames) {
            if ($InputObject.Contains($name)) {
                return $InputObject[$name]
            }
        }
        if ($InputObject -is [System.Collections.Generic.IDictionary[string, object]]) {
            foreach ($name in $dictionaryNames) {
                if ($InputObject.ContainsKey($name)) {
                    return $InputObject[$name]
                }
            }
        }
    }

    $additional = $InputObject.PSObject.Properties.Match('AdditionalProperties').Value
    if (-not $additional) {
        $additional = $InputObject.AdditionalProperties
    }

    if ($additional -and $additional -is [System.Collections.IDictionary]) {
        foreach ($name in $dictionaryNames) {
            if ($additional.Contains($name)) {
                return $additional[$name]
            }
        }
        if ($additional -is [System.Collections.Generic.IDictionary[string, object]]) {
            foreach ($name in $dictionaryNames) {
                if ($additional.ContainsKey($name)) {
                    return $additional[$name]
                }
            }
        }
    }

    return $null
}

function ConvertTo-MfaCanonicalSignIn {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [psobject] $InputObject
    )
    process {
        if (-not $InputObject) {
            return
        }

        $location = Get-MfaDynamicPropertyValue -InputObject $InputObject -PropertyName 'Location'
        $status = Get-MfaDynamicPropertyValue -InputObject $InputObject -PropertyName 'Status'
        $authDetails = Get-MfaDynamicPropertyValue -InputObject $InputObject -PropertyName 'AuthenticationDetails'

        $authMethods = @()
        if ($authDetails) {
            foreach ($detail in $authDetails) {
                $method = Get-MfaDynamicPropertyValue -InputObject $detail -PropertyName 'AuthenticationMethod'
                if ($method) {
                    $authMethods += $method
                }
            }
        }

        $policies = Get-MfaDynamicPropertyValue -InputObject $InputObject -PropertyName 'AuthenticationRequirementPolicies'

        $resultErrorCode = if ($status) { Get-MfaDynamicPropertyValue -InputObject $status -PropertyName 'ErrorCode' } else { $null }
        $resultFailureReason = if ($status) { Get-MfaDynamicPropertyValue -InputObject $status -PropertyName 'FailureReason' } else { $null }
        $resultAdditionalDetails = if ($status) { Get-MfaDynamicPropertyValue -InputObject $status -PropertyName 'AdditionalDetails' } else { $null }

        $result = if ($resultErrorCode -eq 0) { 'Success' } else { 'Failure' }

        [pscustomobject]@{
            RecordType                      = 'SignIn'
            Id                              = Get-MfaDynamicPropertyValue -InputObject $InputObject -PropertyName 'Id'
            TenantId                        = Get-MfaDynamicPropertyValue -InputObject $InputObject -PropertyName 'UserTenantId'
            CreatedDateTime                 = Get-MfaDynamicPropertyValue -InputObject $InputObject -PropertyName 'CreatedDateTime'
            UserId                          = Get-MfaDynamicPropertyValue -InputObject $InputObject -PropertyName 'UserId'
            UserPrincipalName               = Get-MfaDynamicPropertyValue -InputObject $InputObject -PropertyName 'UserPrincipalName'
            UserDisplayName                 = Get-MfaDynamicPropertyValue -InputObject $InputObject -PropertyName 'UserDisplayName'
            AppDisplayName                  = Get-MfaDynamicPropertyValue -InputObject $InputObject -PropertyName 'AppDisplayName'
            AppId                           = Get-MfaDynamicPropertyValue -InputObject $InputObject -PropertyName 'AppId'
            IpAddress                       = Get-MfaDynamicPropertyValue -InputObject $InputObject -PropertyName 'IpAddress'
            LocationCity                    = if ($location) { Get-MfaDynamicPropertyValue -InputObject $location -PropertyName 'City' } else { $null }
            LocationState                   = if ($location) { Get-MfaDynamicPropertyValue -InputObject $location -PropertyName 'State' } else { $null }
            LocationCountryOrRegion         = if ($location) { Get-MfaDynamicPropertyValue -InputObject $location -PropertyName 'CountryOrRegion' } else { $null }
            IsInteractive                   = Get-MfaDynamicPropertyValue -InputObject $InputObject -PropertyName 'IsInteractive'
            AuthenticationRequirement       = Get-MfaDynamicPropertyValue -InputObject $InputObject -PropertyName 'AuthenticationRequirement'
            AuthenticationRequirementPolicies = if ($policies) { ($policies -join ';') } else { $null }
            AuthenticationMethods           = if ($authMethods) { ($authMethods -join ';') } else { $null }
            ConditionalAccessStatus         = Get-MfaDynamicPropertyValue -InputObject $InputObject -PropertyName 'ConditionalAccessStatus'
            RiskDetail                      = Get-MfaDynamicPropertyValue -InputObject $InputObject -PropertyName 'RiskDetail'
            RiskLevelAggregated             = Get-MfaDynamicPropertyValue -InputObject $InputObject -PropertyName 'RiskLevelAggregated'
            RiskState                       = Get-MfaDynamicPropertyValue -InputObject $InputObject -PropertyName 'RiskState'
            CorrelationId                   = Get-MfaDynamicPropertyValue -InputObject $InputObject -PropertyName 'CorrelationId'
            Result                          = $result
            ResultErrorCode                 = $resultErrorCode
            ResultFailureReason             = $resultFailureReason
            ResultAdditionalDetails         = $resultAdditionalDetails
        }
    }
}

function ConvertTo-MfaCanonicalRegistration {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [psobject] $InputObject,
        [string] $UserPrincipalName
    )
    process {
        if (-not $InputObject) {
            return
        }

        $odataType = Get-MfaDynamicPropertyValue -InputObject $InputObject -PropertyName '@odata.type'
        if (-not $odataType) {
            $additional = Get-MfaDynamicPropertyValue -InputObject $InputObject -PropertyName '@odata.type'
            if ($additional) {
                $odataType = $additional
            }
        }
        if (-not $odataType) {
            $additionalProps = Get-MfaDynamicPropertyValue -InputObject $InputObject -PropertyName 'AdditionalProperties'
            if ($additionalProps -and $additionalProps.ContainsKey('@odata.type')) {
                $odataType = $additionalProps['@odata.type']
            }
        }

        $methodType = $null
        if ($odataType) {
            $methodType = $odataType.Split('.')[-1].TrimStart('#')
        }

        $additionalData = @{}
        $additional = Get-MfaDynamicPropertyValue -InputObject $InputObject -PropertyName 'AdditionalProperties'
        if ($additional) {
            foreach ($key in $additional.Keys) {
                if ($key -notin @('@odata.type', 'id', 'displayName', 'createdDateTime', 'lastUpdatedDateTime', 'phoneNumber', 'phoneType', 'isDefault', 'isUsable', 'isEnabled')) {
                    $additionalData[$key] = $additional[$key]
                }
            }
        }

        [pscustomobject]@{
            RecordType          = 'Registration'
            UserPrincipalName   = $UserPrincipalName
            UserId              = Get-MfaDynamicPropertyValue -InputObject $InputObject -PropertyName 'UserId'
            MethodId            = Get-MfaDynamicPropertyValue -InputObject $InputObject -PropertyName 'Id'
            MethodType          = $methodType
            DisplayName         = Get-MfaDynamicPropertyValue -InputObject $InputObject -PropertyName 'DisplayName'
            IsDefault           = Get-MfaDynamicPropertyValue -InputObject $InputObject -PropertyName 'IsDefault'
            IsUsable            = Get-MfaDynamicPropertyValue -InputObject $InputObject -PropertyName 'IsUsable'
            PhoneNumber         = Get-MfaDynamicPropertyValue -InputObject $InputObject -PropertyName 'PhoneNumber'
            PhoneType           = Get-MfaDynamicPropertyValue -InputObject $InputObject -PropertyName 'PhoneType'
            KeyDeviceId         = (Get-MfaDynamicPropertyValue -InputObject $InputObject -PropertyName 'DeviceId') ?? (Get-MfaDynamicPropertyValue -InputObject $InputObject -PropertyName 'KeyId')
            CreatedDateTime     = Get-MfaDynamicPropertyValue -InputObject $InputObject -PropertyName 'CreatedDateTime'
            LastUpdatedDateTime = Get-MfaDynamicPropertyValue -InputObject $InputObject -PropertyName 'LastUpdatedDateTime'
            AdditionalData      = if ($additionalData.Count -gt 0) { $additionalData } else { $null }
        }
    }
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
        [switch] $All,
        [switch] $Normalize,
        [int] $MaxRetries = 3
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
    $results = Invoke-MfaGraphSignInQuery -Filter $filter -All:$All.IsPresent -Top $Top -MaxRetries $MaxRetries

    if ($Normalize) {
        return $results | ConvertTo-MfaCanonicalSignIn
    }

    return $results
}

function Get-MfaEntraRegistration {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('UserPrincipalName')]
        [string] $UserId,
        [switch] $Normalize,
        [int] $MaxRetries = 3
    )
    process {
        $context = Get-MfaGraphContext
        if (-not $context) {
            throw "Microsoft Graph context not found. Run Connect-MgGraph before calling Get-MfaEntraRegistration."
        }

        $results = Invoke-MfaGraphAuthenticationMethodQuery -UserId $UserId -MaxRetries $MaxRetries

        if ($Normalize) {
            return $results | ConvertTo-MfaCanonicalRegistration -UserPrincipalName $UserId
        }

        return $results
    }
}

Export-ModuleMember -Function Get-MfaEnvironmentStatus, Test-MfaGraphPrerequisite, Get-MfaEntraSignIn, Get-MfaEntraRegistration, Connect-MfaGraphDeviceCode, ConvertTo-MfaCanonicalSignIn, ConvertTo-MfaCanonicalRegistration
