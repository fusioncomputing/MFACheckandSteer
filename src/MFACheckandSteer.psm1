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

    $signInCommand = Get-Command -Name Get-MgAuditLogSignIn -ErrorAction SilentlyContinue
    if (-not $signInCommand -or -not $signInCommand.Parameters.ContainsKey('ConsistencyLevel')) {
        $null = $params.Remove('ConsistencyLevel')
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
            'IdentityRiskyUser.Read.All',
            'RoleManagement.Read.Directory'
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

function Get-MfaDirectoryRoleAssignment {
    [CmdletBinding()]
    param(
        [switch] $Normalize,
        [int] $MaxRetries = 3
    )

    $context = Get-MfaGraphContext
    if (-not $context) {
        throw "Microsoft Graph context not found. Run Connect-MgGraph before calling Get-MfaDirectoryRoleAssignment."
    }

    $baseUri = 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments'
    $expandQuery = '$expand=principal($select=id,displayName,userPrincipalName)'
    $expandQuery = $expandQuery.Trim()
    $results = @()
    $nextLink = [string]::Concat($baseUri, '?', $expandQuery)

    while ($nextLink) {
        $response = Invoke-MfaGraphWithRetry -MaxRetries $MaxRetries -Operation {
            Invoke-MgGraphRequest -Method GET -Uri $nextLink
        }

        if ($response.value) {
            $results += $response.value
        }

        $nextLink = Get-MfaDynamicPropertyValue -InputObject $response -PropertyName '@odata.nextLink'
    }

    if (-not $Normalize) {
        return $results
    }

    $roleDefinitionMap = @{}
    try {
        $definitionNextLink = 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions?$select=id,displayName'
        while ($definitionNextLink) {
            $definitionsResponse = Invoke-MfaGraphWithRetry -MaxRetries $MaxRetries -Operation {
                Invoke-MgGraphRequest -Method GET -Uri $definitionNextLink
            }

            if ($definitionsResponse.value) {
                foreach ($definition in $definitionsResponse.value) {
                    $id = Get-MfaDynamicPropertyValue -InputObject $definition -PropertyName 'id'
                    $display = Get-MfaDynamicPropertyValue -InputObject $definition -PropertyName 'displayName'
                    if ($id -and $display) {
                        $roleDefinitionMap[$id] = $display
                    }
                }
            }

            $definitionNextLink = Get-MfaDynamicPropertyValue -InputObject $definitionsResponse -PropertyName '@odata.nextLink'
        }
    }
    catch {
        Write-Warning ("Failed to retrieve role definitions: {0}" -f $_.Exception.Message)
    }

    $normalized = foreach ($assignment in $results) {
        if (-not $assignment) { continue }

        $principal = Get-MfaDynamicPropertyValue -InputObject $assignment -PropertyName 'principal'
        $roleDefinition = Get-MfaDynamicPropertyValue -InputObject $assignment -PropertyName 'roleDefinition'

        $principalUpn = $null
        $principalDisplay = $null
        $principalType = $null
        if ($principal) {
            $principalUpn = Get-MfaDynamicPropertyValue -InputObject $principal -PropertyName 'userPrincipalName'
            $principalDisplay = Get-MfaDynamicPropertyValue -InputObject $principal -PropertyName 'displayName'
            $principalType = Get-MfaDynamicPropertyValue -InputObject $principal -PropertyName '@odata.type'
        }

        if (-not $principalType) {
            $principalType = Get-MfaDynamicPropertyValue -InputObject $assignment -PropertyName 'principalType'
        }

        $roleDisplay = $null
        $roleDefinitionId = Get-MfaDynamicPropertyValue -InputObject $assignment -PropertyName 'roleDefinitionId'
        if ($roleDefinition) {
            $roleDisplay = Get-MfaDynamicPropertyValue -InputObject $roleDefinition -PropertyName 'displayName'
        }
        if (-not $roleDisplay) {
            $roleDisplay = Get-MfaDynamicPropertyValue -InputObject $assignment -PropertyName 'roleDefinitionDisplayName'
        }
        if (-not $roleDisplay -and $roleDefinitionId -and $roleDefinitionMap.ContainsKey([string]$roleDefinitionId)) {
            $roleDisplay = $roleDefinitionMap[[string]$roleDefinitionId]
        }

        [pscustomobject]@{
            RoleAssignmentId          = Get-MfaDynamicPropertyValue -InputObject $assignment -PropertyName 'id'
            RoleDefinitionId          = Get-MfaDynamicPropertyValue -InputObject $assignment -PropertyName 'roleDefinitionId'
            RoleDefinitionDisplayName = $roleDisplay
            RoleDefinitionName        = Get-MfaDynamicPropertyValue -InputObject $assignment -PropertyName 'roleDefinitionName'
            PrincipalId               = Get-MfaDynamicPropertyValue -InputObject $assignment -PropertyName 'principalId'
            UserPrincipalName         = $principalUpn
            UserDisplayName           = $principalDisplay
            PrincipalType             = $principalType
            AssignmentState           = Get-MfaDynamicPropertyValue -InputObject $assignment -PropertyName 'assignmentState'
        }
    }

    return $normalized
}

function ConvertTo-MfaDateTime {
    param(
        $Value
    )

    if ($null -eq $Value -or $Value -eq '') {
        return $null
    }

    if ($Value -is [datetime]) {
        return $Value
    }

    $stringValue = [string]$Value
    [datetime]$parsed = [datetime]::MinValue
    if ([datetime]::TryParse($stringValue, [ref]$parsed)) {
        return $parsed
    }

    return $null
}

$script:MfaDetectionConfigCache = $null
$script:MfaDetectionDefaultConfig = @{
    'MFA-DET-001' = @{
        DormantDays = 90
    }
    'MFA-DET-002' = @{
        ObservationHours     = 24
        RiskDetailExclusions = @('none', 'unknownFutureValue', '')
    }
    'MFA-DET-003' = @{
        PrivilegedRoleIds = @(
            '62e90394-69f5-4237-9190-012177145e10', # Global Administrator
            'e8611ab8-c189-46e8-94e1-60213ab1f814', # Privileged Role Administrator
            '194ae4cb-b126-40b2-bd5b-6091b380977d', # Security Administrator
            'b0f54661-2d74-4c50-afa3-1ec803f12efe'  # Conditional Access Administrator
        )
    }
    'MFA-DET-004' = @{
        ObservationHours    = 24
        FailureThreshold    = 3
        FailureWindowMinutes = 15
    }
    'MFA-DET-005' = @{
        ObservationHours      = 24
        TravelWindowMinutes   = 120
        RequireMfaRequirement = $true
        RequireSuccess        = $true
    }
    'MFA-SCORE' = @{
        ObservationHours       = 24
        FailureThreshold       = 3
        FailureWindowMinutes   = 30
        TravelWindowMinutes    = 120
        RecentRegistrationDays = 7
        WeakMethodTypes        = @(
            'phoneAuthenticationMethod',
            'temporaryAccessPassAuthenticationMethod',
            'smsAuthenticationMethod',
            'voiceAuthenticationMethod'
        )
    }
}

$script:MfaIntegrationDefaultConfig = @{
    Ticketing = @{
        Provider               = 'Generic'
        Endpoint               = $null
        DefaultAssignmentGroup = 'SecOps-MFA'
        Authorization          = @{
            Type           = 'None'
            TokenEnvVar    = $null
            UsernameEnvVar = $null
            PasswordEnvVar = $null
        }
        FallbackPath           = 'tickets/outbox'
    }
    Notifications = @{
        Provider         = 'Generic'
        WebhookUrlEnvVar = $null
        FallbackPath     = 'notifications/outbox'
    }
}

$script:MfaPlaybookDefaultPolicy = @{
    'MFA-PL-001' = @{
        RequiredRoles = @('SecOps-IAM')
    }
    'MFA-PL-002' = @{
        RequiredRoles = @('SecOps-IR')
    }
    'MFA-PL-003' = @{
        RequiredRoles = @('SecOps-IAM')
    }
    'MFA-PL-004' = @{
        RequiredRoles = @('SecOps-Triage')
    }
    'MFA-PL-005' = @{
        RequiredRoles = @('SecOps-IR')
    }
    'MFA-PL-006' = @{
        RequiredRoles = @('SecOps-ThreatHunting')
    }
}

function Get-MfaPlaybookPolicyPath {
    $customPath = [Environment]::GetEnvironmentVariable('MfaPlaybookPolicyPath', 'Process')
    if (-not $customPath) {
        $moduleRoot = Split-Path -Parent $PSScriptRoot
        $customPath = Join-Path -Path $moduleRoot -ChildPath 'config/playbooks.json'
    }

    return $customPath
}

function Get-MfaDetectionConfigPath {
    $customPath = [Environment]::GetEnvironmentVariable('MfaDetectionConfigurationPath', 'Process')
    if (-not $customPath) {
        $moduleRoot = Split-Path -Parent $PSScriptRoot
        $customPath = Join-Path -Path $moduleRoot -ChildPath 'config/detections.json'
    }

    return $customPath
}

function Get-MfaIntegrationConfigPath {
    $customPath = [Environment]::GetEnvironmentVariable('MfaIntegrationConfigurationPath', 'Process')
    if (-not $customPath) {
        $moduleRoot = Split-Path -Parent $PSScriptRoot
        $customPath = Join-Path -Path $moduleRoot -ChildPath 'config/integrations.json'
    }

    return $customPath
}

function ConvertTo-MfaConfigObject {
    param(
        $Value
    )

    if ($null -eq $Value) {
        return $null
    }

    if ($Value -is [System.Collections.IDictionary]) {
        $copy = [ordered]@{}
        foreach ($key in $Value.Keys) {
            $copy[$key] = ConvertTo-MfaConfigObject -Value $Value[$key]
        }
        return [pscustomobject]$copy
    }
    elseif ($Value -is [System.Collections.IEnumerable] -and -not ($Value -is [string])) {
        $list = @()
        foreach ($item in $Value) {
            $list += ConvertTo-MfaConfigObject -Value $item
        }
        return $list
    }

    return $Value
}

function Set-MfaConfigInt {
    param(
        [hashtable] $Target,
        [string] $Name,
        [object] $Value,
        [int] $Min = 1,
        [int] $Max = [int]::MaxValue
    )

    if ($null -eq $Value -or $Value -eq '') {
        return
    }

    try {
        $converted = [int]$Value
        if ($converted -lt $Min -or $converted -gt $Max) {
            Write-Warning "Configuration value '$Name' ($converted) is outside the allowed range $Min-$Max. Skipping override."
            return
        }

        $Target[$Name] = $converted
    }
    catch {
        Write-Warning "Configuration value '$Name' could not be converted to an integer. Skipping override."
    }
}

function Set-MfaConfigStringArray {
    param(
        [hashtable] $Target,
        [string] $Name,
        [object] $Value
    )

    if ($null -eq $Value) {
        return
    }

    $items = @()

    if ($Value -is [System.Collections.IEnumerable] -and -not ($Value -is [string])) {
        foreach ($entry in $Value) {
            if ($null -ne $entry -and $entry -ne '') {
                $items += [string]$entry
            }
        }
    }
    else {
        $items += [string]$Value
    }

    if ($items.Count -gt 0) {
        $Target[$Name] = $items
    }
}

function Initialize-MfaDetectionConfiguration {
    $defaults = $script:MfaDetectionDefaultConfig
    $effective = @{}
    foreach ($key in $defaults.Keys) {
        $copy = @{}
        foreach ($param in $defaults[$key].Keys) {
            $copy[$param] = $defaults[$key][$param]
        }
        $effective[$key] = $copy
    }

    $path = Get-MfaDetectionConfigPath
    if (Test-Path $path) {
        try {
            $raw = Get-Content -Path $path -Raw
            if ($raw) {
                $overrides = ConvertFrom-Json -InputObject $raw -AsHashtable
                foreach ($entry in $overrides.GetEnumerator()) {
                    $key = [string]$entry.Key
                    $value = $entry.Value
                    if (-not $effective.ContainsKey($key)) {
                        $effective[$key] = @{}
                    }

                    $target = $effective[$key]

                    foreach ($paramEntry in $value.GetEnumerator()) {
                        $paramName = [string]$paramEntry.Key
                        $paramValue = $paramEntry.Value

                        switch ($key) {
                            'MFA-DET-001' {
                                if ($paramName -eq 'DormantDays') {
                                    Set-MfaConfigInt -Target $target -Name 'DormantDays' -Value $paramValue -Min 1 -Max 365
                                }
                            }
                            'MFA-DET-002' {
                                switch ($paramName) {
                                    'ObservationHours' {
                                        Set-MfaConfigInt -Target $target -Name 'ObservationHours' -Value $paramValue -Min 1 -Max 168
                                    }
                                    'RiskDetailExclusions' {
                                        Set-MfaConfigStringArray -Target $target -Name 'RiskDetailExclusions' -Value $paramValue
                                    }
                                }
                            }
                            'MFA-DET-003' {
                                switch ($paramName) {
                                    'PrivilegedRoleIds' {
                                        Set-MfaConfigStringArray -Target $target -Name 'PrivilegedRoleIds' -Value $paramValue
                                    }
                                }
                            }
                            'MFA-DET-004' {
                                switch ($paramName) {
                                    'ObservationHours' {
                                        Set-MfaConfigInt -Target $target -Name 'ObservationHours' -Value $paramValue -Min 1 -Max 168
                                    }
                                    'FailureThreshold' {
                                        Set-MfaConfigInt -Target $target -Name 'FailureThreshold' -Value $paramValue -Min 1 -Max 10
                                    }
                                    'FailureWindowMinutes' {
                                        Set-MfaConfigInt -Target $target -Name 'FailureWindowMinutes' -Value $paramValue -Min 1 -Max 720
                                    }
                                }
                            }
                            'MFA-DET-005' {
                                switch ($paramName) {
                                    'ObservationHours' {
                                        Set-MfaConfigInt -Target $target -Name 'ObservationHours' -Value $paramValue -Min 1 -Max 168
                                    }
                                    'TravelWindowMinutes' {
                                        Set-MfaConfigInt -Target $target -Name 'TravelWindowMinutes' -Value $paramValue -Min 1 -Max 720
                                    }
                                }
                            }
                            'MFA-SCORE' {
                                switch ($paramName) {
                                    'ObservationHours' {
                                        Set-MfaConfigInt -Target $target -Name 'ObservationHours' -Value $paramValue -Min 1 -Max 168
                                    }
                                    'FailureThreshold' {
                                        Set-MfaConfigInt -Target $target -Name 'FailureThreshold' -Value $paramValue -Min 1 -Max 10
                                    }
                                    'FailureWindowMinutes' {
                                        Set-MfaConfigInt -Target $target -Name 'FailureWindowMinutes' -Value $paramValue -Min 1 -Max 720
                                    }
                                    'TravelWindowMinutes' {
                                        Set-MfaConfigInt -Target $target -Name 'TravelWindowMinutes' -Value $paramValue -Min 1 -Max 720
                                    }
                                    'RecentRegistrationDays' {
                                        Set-MfaConfigInt -Target $target -Name 'RecentRegistrationDays' -Value $paramValue -Min 1 -Max 30
                                    }
                                    'WeakMethodTypes' {
                                        Set-MfaConfigStringArray -Target $target -Name 'WeakMethodTypes' -Value $paramValue
                                    }
                                }
                            }
                            default {
                                $target[$paramName] = $paramValue
                            }
                        }
                    }
                }
            }
        }
        catch {
            Write-Warning "Failed to parse detection configuration file at '$path'. Using defaults. Error: $($_.Exception.Message)"
        }
    }

    $script:MfaDetectionConfigCache = @{}
    foreach ($entry in $effective.GetEnumerator()) {
        $script:MfaDetectionConfigCache[$entry.Key] = [pscustomobject]$entry.Value
    }
    $script:MfaDetectionConfigCache['__Metadata'] = [pscustomobject]@{
        Path = $path
    }
}

function Get-MfaDetectionConfiguration {
    [CmdletBinding()]
    param(
        [string] $DetectionId,
        [switch] $Refresh
    )

    if ($Refresh -or -not $script:MfaDetectionConfigCache) {
        Initialize-MfaDetectionConfiguration
    }

    if ($DetectionId) {
        if ($script:MfaDetectionConfigCache.ContainsKey($DetectionId)) {
            return $script:MfaDetectionConfigCache[$DetectionId]
        }

        return $null
    }

    return $script:MfaDetectionConfigCache
}

$script:MfaIntegrationConfigCache = $null

function Initialize-MfaIntegrationConfig {
    $effective = @{}
    foreach ($entry in $script:MfaIntegrationDefaultConfig.GetEnumerator()) {
        $copy = [ordered]@{}
        foreach ($key in $entry.Value.Keys) {
            $copy[$key] = ConvertTo-MfaConfigObject -Value $entry.Value[$key]
        }
        $effective[$entry.Key] = $copy
    }

    $path = Get-MfaIntegrationConfigPath
    if (Test-Path $path) {
        try {
            $raw = Get-Content -Path $path -Raw
            if ($raw) {
                $overrides = ConvertFrom-Json -InputObject $raw -AsHashtable
                foreach ($entry in $overrides.GetEnumerator()) {
                    $area = [string]$entry.Key
                    $value = $entry.Value
                    if (-not $effective.ContainsKey($area)) {
                        $effective[$area] = [ordered]@{}
                    }

                    foreach ($prop in $value.GetEnumerator()) {
                        $name = [string]$prop.Key
                        $propValue = $prop.Value
                        $effective[$area][$name] = ConvertTo-MfaConfigObject -Value $propValue
                    }
                }
            }
        }
        catch {
            Write-Warning "Failed to parse integration configuration file at '$path'. Using defaults. Error: $($_.Exception.Message)"
        }
    }

    $script:MfaIntegrationConfigCache = @{}
    foreach ($entry in $effective.GetEnumerator()) {
        $script:MfaIntegrationConfigCache[$entry.Key] = [pscustomobject]$entry.Value
    }
    $script:MfaIntegrationConfigCache['__Metadata'] = [pscustomobject]@{
        Path = $path
    }
}

function Get-MfaIntegrationConfig {
    [CmdletBinding()]
    param(
        [string] $Area,
        [switch] $Refresh
    )

    if ($Refresh -or -not $script:MfaIntegrationConfigCache) {
        Initialize-MfaIntegrationConfig
    }

    if ($Area) {
        if ($script:MfaIntegrationConfigCache.ContainsKey($Area)) {
            return $script:MfaIntegrationConfigCache[$Area]
        }

        return $null
    }

    return $script:MfaIntegrationConfigCache
}

$script:MfaPlaybookPolicyCache = $null

function Initialize-MfaPlaybookPolicy {
    $effective = @{}
    foreach ($entry in $script:MfaPlaybookDefaultPolicy.GetEnumerator()) {
        $effective[$entry.Key] = @{}
        foreach ($key in $entry.Value.Keys) {
            $effective[$entry.Key][$key] = $entry.Value[$key]
        }
    }

    $path = Get-MfaPlaybookPolicyPath
    if (Test-Path $path) {
        try {
            $raw = Get-Content -Path $path -Raw
            if ($raw) {
                $overrides = ConvertFrom-Json -InputObject $raw -AsHashtable
                foreach ($policyEntry in $overrides.GetEnumerator()) {
                    $playbookId = [string]$policyEntry.Key
                    $definition = $policyEntry.Value
                    if (-not $effective.ContainsKey($playbookId)) {
                        $effective[$playbookId] = @{}
                    }

                    foreach ($property in $definition.GetEnumerator()) {
                        $name = [string]$property.Key
                        $value = $property.Value
                        switch ($name) {
                            'RequiredRoles' {
                                $roles = @()
                                if ($value -is [System.Collections.IEnumerable] -and -not ($value -is [string])) {
                                    foreach ($role in $value) {
                                        if ($role) { $roles += [string]$role }
                                    }
                                }
                                elseif ($value) {
                                    $roles += [string]$value
                                }
                                if ($roles.Count -gt 0) {
                                    $effective[$playbookId]['RequiredRoles'] = $roles
                                }
                            }
                            default {
                                $effective[$playbookId][$name] = $value
                            }
                        }
                    }
                }
            }
        }
        catch {
            Write-Warning "Failed to parse playbook policy file at '$path'. Using defaults. Error: $($_.Exception.Message)"
        }
    }

    $script:MfaPlaybookPolicyCache = @{}
    foreach ($entry in $effective.GetEnumerator()) {
        $script:MfaPlaybookPolicyCache[$entry.Key] = [pscustomobject]$entry.Value
    }
}

function Get-MfaPlaybookPolicy {
    [CmdletBinding()]
    param(
        [string] $PlaybookId,
        [switch] $Refresh
    )

    if ($Refresh -or -not $script:MfaPlaybookPolicyCache) {
        Initialize-MfaPlaybookPolicy
    }

    if ($PlaybookId) {
        if ($script:MfaPlaybookPolicyCache.ContainsKey($PlaybookId)) {
            return $script:MfaPlaybookPolicyCache[$PlaybookId]
        }
        return $null
    }

    return $script:MfaPlaybookPolicyCache
}

function Get-MfaPlaybookCurrentRoles {
    param(
        [string[]] $ExplicitRoles
    )

    if ($ExplicitRoles) {
        return @($ExplicitRoles | Where-Object { $_ }) | ForEach-Object { $_.Trim() } | Where-Object { $_ }
    }

    $raw = [Environment]::GetEnvironmentVariable('MFA_PLAYBOOK_ROLES', 'Process')
    if (-not $raw) {
        $raw = [Environment]::GetEnvironmentVariable('MFA_PLAYBOOK_ROLES', 'Machine')
    }

    if (-not $raw) {
        return @()
    }

    return @($raw -split '[,;]' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
}

function Test-MfaPlaybookAuthorization {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $PlaybookId,
        [string[]] $UserRoles,
        [switch] $WarnOnly
    )

    $policy = Get-MfaPlaybookPolicy -PlaybookId $PlaybookId
    $requiredRoles = @()
    if ($policy -and $policy.PSObject.Properties.Name -contains 'RequiredRoles') {
        $requiredRoles = @($policy.RequiredRoles | Where-Object { $_ })
    }

    if (-not $requiredRoles -or $requiredRoles.Count -eq 0) {
        return $true
    }

    $roles = Get-MfaPlaybookCurrentRoles -ExplicitRoles $UserRoles
    $missing = @($requiredRoles | Where-Object { $_ -notin $roles })

    if ($missing.Count -gt 0) {
        $message = "Operator lacks required playbook role(s) for $PlaybookId. Missing: $($missing -join ', '). Set MFA_PLAYBOOK_ROLES or update playbook policy."
        if ($WarnOnly) {
            Write-Warning $message
            return $false
        }

        throw $message
    }

    return $true
}

$script:MfaDetectionMetadata = $null

function Initialize-MfaDetectionMetadata {
    if ($script:MfaDetectionMetadata) {
        return
    }

    $script:MfaDetectionMetadata = @{
        'MFA-DET-001' = @{
            FrameworkTags = @('ATTACK:T1078')
            NistFunctions = @('PR.AC-1', 'PR.AC-6')
            ReportingTags = @('Configuration', 'MFA', 'DormantMethod', 'Risk-{Severity}')
            ControlOwner = 'SecOps IAM Team'
            ResponseSlaHours = 72
            ReviewCadenceDays = 90
        }
        'MFA-DET-002' = @{
            FrameworkTags = @('ATTACK:T1110.003', 'ATTACK:T1621')
            NistFunctions = @('DE.AE-2', 'DE.CM-7')
            ReportingTags = @('Authentication', 'HighRiskSignin', 'Risk-{Severity}')
            ControlOwner = 'SecOps Incident Response'
            ResponseSlaHours = 4
            ReviewCadenceDays = 30
        }
        'MFA-DET-003' = @{
            FrameworkTags = @('ATTACK:T1078', 'ATTACK:T1098')
            NistFunctions = @('PR.AC-4', 'PR.IP-1')
            ReportingTags = @('Configuration', 'PrivilegedRole', 'Risk-{Severity}')
            ControlOwner = 'SecOps IAM Team'
            ResponseSlaHours = 24
            ReviewCadenceDays = 30
        }
        'MFA-DET-004' = @{
            FrameworkTags = @('ATTACK:T1110', 'ATTACK:T1621')
            NistFunctions = @('DE.AE-2', 'DE.CM-7')
            ReportingTags = @('Authentication', 'RepeatedFailure', 'Risk-{Severity}')
            ControlOwner = 'SecOps Incident Response'
            ResponseSlaHours = 8
            ReviewCadenceDays = 30
        }
        'MFA-DET-005' = @{
            FrameworkTags = @('ATTACK:T1078', 'ATTACK:T1110')
            NistFunctions = @('DE.AE-2', 'DE.CM-7')
            ReportingTags = @('Authentication', 'ImpossibleTravel', 'Risk-{Severity}')
            ControlOwner = 'SecOps Threat Hunting'
            ResponseSlaHours = 6
            ReviewCadenceDays = 30
        }
        'MFA-SCORE' = @{
            FrameworkTags = @('ATTACK:T1110', 'ATTACK:T1078', 'ATTACK:T1621')
            NistFunctions = @('DE.AE-2', 'DE.AE-3', 'DE.CM-1')
            ReportingTags = @('Aggregated', 'SuspiciousScore', 'Risk-{Severity}')
            ControlOwner = 'SecOps Triage Desk'
            ResponseSlaHours = @{
                Critical = 8
                High     = 24
                Default  = 24
            }
            ReviewCadenceDays = 14
        }
    }
}

function Resolve-MfaDetectionMetadata {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $DetectionId,
        [string] $Severity
    )

    Initialize-MfaDetectionMetadata
    $entry = $script:MfaDetectionMetadata[$DetectionId]
    if (-not $entry) {
        return $null
    }

    function Get-EntryValue {
        param($Source, [string] $Name)

        if ($Source -is [System.Collections.IDictionary]) {
            if ($Source.Contains($Name)) {
                return $Source[$Name]
            }
            return $null
        }

        $prop = $Source.PSObject.Properties[$Name]
        if ($prop) {
            return $prop.Value
        }

        return $null
    }

    $resolvedTags = @()
    foreach ($tag in (@(Get-EntryValue -Source $entry -Name 'ReportingTags') | Where-Object { $_ })) {
        if ($Severity -and $tag -like '*{Severity}*') {
            $resolvedTags += ($tag -replace '\{Severity\}', $Severity)
        }
        else {
            $resolvedTags += $tag
        }
    }

    $slaValue = $null
    $rawSla = Get-EntryValue -Source $entry -Name 'ResponseSlaHours'
    if ($null -ne $rawSla) {
        if ($rawSla -is [hashtable]) {
            if ($Severity -and $rawSla.ContainsKey($Severity)) {
                $slaValue = [int]$rawSla[$Severity]
            }
            elseif ($rawSla.ContainsKey('Default')) {
                $slaValue = [int]$rawSla['Default']
            }
            elseif ($rawSla.Keys.Count -gt 0) {
                $firstKey = ($rawSla.Keys | Select-Object -First 1)
                $slaValue = [int]$rawSla[$firstKey]
            }
        }
        elseif ($rawSla -ne $null -and $rawSla -ne '') {
            $slaValue = [int]$rawSla
        }
    }

    $controlOwner = Get-EntryValue -Source $entry -Name 'ControlOwner'
    if ($controlOwner) {
        $controlOwner = [string]$controlOwner
    }

    $reviewCadence = Get-EntryValue -Source $entry -Name 'ReviewCadenceDays'
    if ($reviewCadence) {
        $reviewCadence = [int]$reviewCadence
    }

    $frameworkTags = Get-EntryValue -Source $entry -Name 'FrameworkTags'
    $nistFunctions = Get-EntryValue -Source $entry -Name 'NistFunctions'

    return [pscustomobject]@{
        FrameworkTags = @($frameworkTags | Where-Object { $_ })
        NistFunctions = @($nistFunctions | Where-Object { $_ })
        ReportingTags = $resolvedTags
        ControlOwner  = $controlOwner
        ResponseSlaHours = $slaValue
        ReviewCadenceDays = $reviewCadence
    }
}

function Invoke-MfaDetectionDormantMethod {
    param(
        [psobject[]] $RegistrationData,
        [int] $DormantDays = 90,
        [datetime] $ReferenceTime = (Get-Date)
    )

    $effectiveDormantDays = $DormantDays
    if (-not $PSBoundParameters.ContainsKey('DormantDays')) {
        $config = Get-MfaDetectionConfiguration -DetectionId 'MFA-DET-001'
        if ($config -and $config.PSObject.Properties.Name -contains 'DormantDays' -and $config.DormantDays) {
            $effectiveDormantDays = [math]::Max(1, [int]$config.DormantDays)
        }
    }

    if (-not $RegistrationData) {
        $RegistrationData = Get-MfaEntraRegistration -Normalize
    }

    if (-not $RegistrationData) {
        return @()
    }

    $cutoff = $ReferenceTime.AddDays(-[math]::Abs($effectiveDormantDays))

    $detections = foreach ($record in $RegistrationData) {
        if (-not $record) { continue }
        if (-not $record.IsDefault) { continue }

        $lastUpdated = ConvertTo-MfaDateTime -Value $record.LastUpdatedDateTime

        $isDormant = $false
        if (-not $lastUpdated) {
            $isDormant = $true
        }
        elseif ($lastUpdated -lt $cutoff) {
            $isDormant = $true
        }

        if ($isDormant) {
            $metadata = Resolve-MfaDetectionMetadata -DetectionId 'MFA-DET-001' -Severity 'Medium'
            [pscustomobject]@{
                DetectionId          = 'MFA-DET-001'
                UserPrincipalName    = $record.UserPrincipalName
                MethodType           = $record.MethodType
                LastUpdatedDateTime  = $lastUpdated
                Severity             = 'Medium'
                Source               = 'Get-MfaEntraRegistration'
                FrameworkTags        = $metadata.FrameworkTags
                NistFunctions        = $metadata.NistFunctions
                ReportingTags        = $metadata.ReportingTags
                ControlOwner         = $metadata.ControlOwner
                ResponseSlaHours     = $metadata.ResponseSlaHours
                ReviewCadenceDays    = $metadata.ReviewCadenceDays
            }
        }
    }

    return $detections
}

function Invoke-MfaDetectionHighRiskSignin {
    param(
        [psobject[]] $SignInData,
        [int] $ObservationHours = 24,
        [datetime] $ReferenceTime = (Get-Date),
        [string[]] $RiskDetailExclusions
    )

    $effectiveObservationHours = $ObservationHours
    $effectiveRiskDetailExclusions = if ($RiskDetailExclusions) { @($RiskDetailExclusions) } else { $null }

    if (-not $PSBoundParameters.ContainsKey('ObservationHours') -or -not $PSBoundParameters.ContainsKey('RiskDetailExclusions')) {
        $config = Get-MfaDetectionConfiguration -DetectionId 'MFA-DET-002'
        if ($config) {
            if (-not $PSBoundParameters.ContainsKey('ObservationHours') -and $config.PSObject.Properties.Name -contains 'ObservationHours' -and $config.ObservationHours) {
                $effectiveObservationHours = [math]::Max(1, [int]$config.ObservationHours)
            }
            if (-not $PSBoundParameters.ContainsKey('RiskDetailExclusions') -and $config.PSObject.Properties.Name -contains 'RiskDetailExclusions' -and $config.RiskDetailExclusions) {
                $effectiveRiskDetailExclusions = @($config.RiskDetailExclusions)
            }
        }
    }

    if (-not $effectiveRiskDetailExclusions) {
        $effectiveRiskDetailExclusions = @('none', 'unknownFutureValue', '')
    }

    if (-not $SignInData) {
        $start = $ReferenceTime.AddHours(-[math]::Abs($effectiveObservationHours))
        $SignInData = Get-MfaEntraSignIn -Normalize -StartTime $start -EndTime $ReferenceTime
    }

    if (-not $SignInData) {
        return @()
    }

    $windowStart = $ReferenceTime.AddHours(-[math]::Abs($effectiveObservationHours))

    $detections = foreach ($record in $SignInData) {
        if (-not $record) { continue }

        $created = ConvertTo-MfaDateTime -Value $record.CreatedDateTime
        if (-not $created) {
            $created = [datetime]::MinValue
        }
        if ($created -lt $windowStart -or $created -gt $ReferenceTime) {
            continue
        }

        if ($record.Result -ne 'Success') { continue }

        $riskState = $record.RiskState
        $riskDetail = $record.RiskDetail

        $isRisky = $false
        if ($riskState -eq 'atRisk') {
            $isRisky = $true
        }
        elseif ($riskDetail -and ($effectiveRiskDetailExclusions -notcontains $riskDetail)) {
            $isRisky = $true
        }

        if ($isRisky) {
            $metadata = Resolve-MfaDetectionMetadata -DetectionId 'MFA-DET-002' -Severity 'High'
            [pscustomobject]@{
                DetectionId          = 'MFA-DET-002'
                UserPrincipalName    = $record.UserPrincipalName
                CreatedDateTime      = $created
                RiskState            = $riskState
                RiskDetail           = $riskDetail
                AuthenticationMethods = $record.AuthenticationMethods
                Severity             = 'High'
                CorrelationId        = $record.CorrelationId
                Source               = 'Get-MfaEntraSignIn'
                FrameworkTags        = $metadata.FrameworkTags
                NistFunctions        = $metadata.NistFunctions
                ReportingTags        = $metadata.ReportingTags
                ControlOwner         = $metadata.ControlOwner
                ResponseSlaHours     = $metadata.ResponseSlaHours
                ReviewCadenceDays    = $metadata.ReviewCadenceDays
            }
        }
    }

    return $detections
}

function Invoke-MfaDetectionRepeatedMfaFailure {
    [CmdletBinding()]
    param(
        [psobject[]] $SignInData,
        [int] $ObservationHours = 24,
        [int] $FailureThreshold = 3,
        [int] $FailureWindowMinutes = 15,
        [datetime] $ReferenceTime = (Get-Date)
    )

    $effectiveObservationHours = $ObservationHours
    $effectiveFailureThreshold = $FailureThreshold
    $effectiveFailureWindowMinutes = $FailureWindowMinutes

    if (-not $PSBoundParameters.ContainsKey('ObservationHours') -or
        -not $PSBoundParameters.ContainsKey('FailureThreshold') -or
        -not $PSBoundParameters.ContainsKey('FailureWindowMinutes')) {
        $config = Get-MfaDetectionConfiguration -DetectionId 'MFA-DET-004'
        if ($config) {
            if (-not $PSBoundParameters.ContainsKey('ObservationHours') -and
                $config.PSObject.Properties.Name -contains 'ObservationHours' -and
                $config.ObservationHours) {
                $effectiveObservationHours = [int]$config.ObservationHours
            }
            if (-not $PSBoundParameters.ContainsKey('FailureThreshold') -and
                $config.PSObject.Properties.Name -contains 'FailureThreshold' -and
                $config.FailureThreshold) {
                $effectiveFailureThreshold = [int]$config.FailureThreshold
            }
            if (-not $PSBoundParameters.ContainsKey('FailureWindowMinutes') -and
                $config.PSObject.Properties.Name -contains 'FailureWindowMinutes' -and
                $config.FailureWindowMinutes) {
                $effectiveFailureWindowMinutes = [int]$config.FailureWindowMinutes
            }
        }
    }

    $effectiveObservationHours = [math]::Max(1, [math]::Abs($effectiveObservationHours))
    $effectiveFailureThreshold = [math]::Max(1, [int][math]::Abs($effectiveFailureThreshold))
    $effectiveFailureWindowMinutes = [math]::Max(1, [int][math]::Abs($effectiveFailureWindowMinutes))

    $windowEnd = $ReferenceTime
    $windowStart = $ReferenceTime.AddHours(-$effectiveObservationHours)

    if (-not $SignInData) {
        $SignInData = Get-MfaEntraSignIn -Normalize -StartTime $windowStart -EndTime $windowEnd
    }

    if (-not $SignInData) {
        return @()
    }

    $normalized = foreach ($record in $SignInData) {
        if (-not $record) { continue }
        $user = $record.UserPrincipalName
        if (-not $user) { continue }
        $created = ConvertTo-MfaDateTime -Value $record.CreatedDateTime
        if (-not $created) { continue }
        if ($created -lt $windowStart -or $created -gt $windowEnd) { continue }

        [pscustomobject]@{
            Raw                 = $record
            UserPrincipalName   = $user
            CreatedDateTime     = $created
            Result              = $record.Result
            ResultFailureReason = $record.ResultFailureReason
            ResultErrorCode     = $record.ResultErrorCode
        }
    }

    if (-not $normalized) {
        return @()
    }

    $failureWindow = [TimeSpan]::FromMinutes($effectiveFailureWindowMinutes)
    $metadata = Resolve-MfaDetectionMetadata -DetectionId 'MFA-DET-004' -Severity 'Medium'
    $detections = @()

    $groups = $normalized | Group-Object -Property UserPrincipalName
    foreach ($group in $groups) {
        $userFailures = $group.Group | Where-Object { $_.Result -eq 'Failure' } | Sort-Object -Property CreatedDateTime
        if (-not $userFailures) { continue }

        $queue = [System.Collections.Generic.Queue[psobject]]::new()
        foreach ($failure in $userFailures) {
            while ($queue.Count -gt 0 -and (($failure.CreatedDateTime - $queue.Peek().CreatedDateTime) -gt $failureWindow)) {
                [void]$queue.Dequeue()
            }

            $queue.Enqueue($failure)

            if ($queue.Count -ge $effectiveFailureThreshold) {
                $windowFailures = $queue.ToArray()
                $windowStartTime = $windowFailures[0].CreatedDateTime
                $windowEndTime = $windowFailures[-1].CreatedDateTime
                $reasons = $windowFailures | ForEach-Object { $_.ResultFailureReason } | Where-Object { $_ } | Sort-Object -Unique
                $errorCodes = $windowFailures | ForEach-Object { $_.ResultErrorCode } | Where-Object { $_ -ne $null } | Sort-Object -Unique
                $correlationIds = $windowFailures | ForEach-Object { $_.Raw.CorrelationId } | Where-Object { $_ } | Sort-Object -Unique

                $detections += [pscustomobject]@{
                    DetectionId          = 'MFA-DET-004'
                    UserPrincipalName    = $group.Name
                    WindowStart          = $windowStartTime
                    WindowEnd            = $windowEndTime
                    FailureCount         = $queue.Count
                    FailureWindowMinutes = [int][math]::Round($failureWindow.TotalMinutes, 0)
                    FailureReasons       = if ($reasons) { $reasons -join '; ' } else { $null }
                    FailureErrorCodes    = if ($errorCodes) { $errorCodes } else { $null }
                    CorrelationIds       = if ($correlationIds) { $correlationIds } else { $null }
                    Severity             = 'Medium'
                    Source               = 'Get-MfaEntraSignIn'
                    FrameworkTags        = $metadata.FrameworkTags
                    NistFunctions        = $metadata.NistFunctions
                    ReportingTags        = $metadata.ReportingTags
                    ControlOwner         = $metadata.ControlOwner
                    ResponseSlaHours     = $metadata.ResponseSlaHours
                    ReviewCadenceDays    = $metadata.ReviewCadenceDays
                }

                break
            }
        }
    }

    return $detections | Sort-Object -Property UserPrincipalName
}

function Invoke-MfaDetectionImpossibleTravelSuccess {
    [CmdletBinding()]
    param(
        [psobject[]] $SignInData,
        [int] $ObservationHours = 24,
        [int] $TravelWindowMinutes = 120,
        [bool] $RequireMfaRequirement = $true,
        [bool] $RequireSuccess = $true,
        [datetime] $ReferenceTime = (Get-Date)
    )

    $effectiveObservationHours = $ObservationHours
    $effectiveTravelWindowMinutes = $TravelWindowMinutes
    $effectiveRequireMfaRequirement = $RequireMfaRequirement
    $effectiveRequireSuccess = $RequireSuccess

    if (-not $PSBoundParameters.ContainsKey('ObservationHours') -or
        -not $PSBoundParameters.ContainsKey('TravelWindowMinutes') -or
        -not $PSBoundParameters.ContainsKey('RequireMfaRequirement') -or
        -not $PSBoundParameters.ContainsKey('RequireSuccess')) {
        $config = Get-MfaDetectionConfiguration -DetectionId 'MFA-DET-005'
        if ($config) {
            if (-not $PSBoundParameters.ContainsKey('ObservationHours') -and
                $config.PSObject.Properties.Name -contains 'ObservationHours' -and
                $config.ObservationHours) {
                $effectiveObservationHours = [int]$config.ObservationHours
            }
            if (-not $PSBoundParameters.ContainsKey('TravelWindowMinutes') -and
                $config.PSObject.Properties.Name -contains 'TravelWindowMinutes' -and
                $config.TravelWindowMinutes) {
                $effectiveTravelWindowMinutes = [int]$config.TravelWindowMinutes
            }
            if (-not $PSBoundParameters.ContainsKey('RequireMfaRequirement') -and
                $config.PSObject.Properties.Name -contains 'RequireMfaRequirement') {
                $effectiveRequireMfaRequirement = [bool]$config.RequireMfaRequirement
            }
            if (-not $PSBoundParameters.ContainsKey('RequireSuccess') -and
                $config.PSObject.Properties.Name -contains 'RequireSuccess') {
                $effectiveRequireSuccess = [bool]$config.RequireSuccess
            }
        }
    }

    $effectiveObservationHours = [math]::Max(1, [math]::Abs($effectiveObservationHours))
    $effectiveTravelWindowMinutes = [math]::Max(1, [int][math]::Abs($effectiveTravelWindowMinutes))

    $windowEnd = $ReferenceTime
    $windowStart = $ReferenceTime.AddHours(-$effectiveObservationHours)

    if (-not $SignInData) {
        $SignInData = Get-MfaEntraSignIn -Normalize -StartTime $windowStart -EndTime $windowEnd
    }

    if (-not $SignInData) {
        return @()
    }

    $normalized = foreach ($record in $SignInData) {
        if (-not $record) { continue }
        $user = $record.UserPrincipalName
        if (-not $user) { continue }
        $created = ConvertTo-MfaDateTime -Value $record.CreatedDateTime
        if (-not $created) { continue }
        if ($created -lt $windowStart -or $created -gt $windowEnd) { continue }

        [pscustomobject]@{
            Raw                         = $record
            UserPrincipalName           = $user
            CreatedDateTime             = $created
            LocationCountryOrRegion     = $record.LocationCountryOrRegion
            LocationCity                = $record.LocationCity
            IpAddress                   = $record.IpAddress
            Result                      = $record.Result
            AuthenticationRequirement   = $record.AuthenticationRequirement
            AuthenticationMethods       = $record.AuthenticationMethods
        }
    }

    if (-not $normalized) {
        return @()
    }

    $travelWindow = [TimeSpan]::FromMinutes($effectiveTravelWindowMinutes)
    $metadata = Resolve-MfaDetectionMetadata -DetectionId 'MFA-DET-005' -Severity 'High'
    $detections = @()

    $groups = $normalized | Group-Object -Property UserPrincipalName
    foreach ($group in $groups) {
        $records = $group.Group | Sort-Object -Property CreatedDateTime
        if ($records.Count -lt 2) { continue }

        $detected = $false
        for ($i = 1; $i -lt $records.Count -and -not $detected; $i++) {
            $current = $records[$i]

            if ($effectiveRequireSuccess -and $current.Result -ne 'Success') {
                continue
            }

            if ($effectiveRequireMfaRequirement) {
                $requiresMfa = $false
                if ($current.AuthenticationRequirement -and ($current.AuthenticationRequirement -match 'mfa')) {
                    $requiresMfa = $true
                }
                elseif ($current.AuthenticationMethods -and ($current.AuthenticationMethods -match ';' -or $current.AuthenticationMethods -match 'mfa')) {
                    $requiresMfa = $true
                }

                if (-not $requiresMfa) {
                    continue
                }
            }

            for ($j = $i - 1; $j -ge 0; $j--) {
                $previous = $records[$j]
                $delta = $current.CreatedDateTime - $previous.CreatedDateTime
                if ($delta -gt $travelWindow) {
                    break
                }

                $prevCountry = $previous.LocationCountryOrRegion
                $currCountry = $current.LocationCountryOrRegion

                if (-not $prevCountry -or -not $currCountry) {
                    continue
                }
                if ($prevCountry -eq $currCountry) {
                    continue
                }

                $minutes = [int][math]::Round([math]::Abs($delta.TotalMinutes), 0)
                $detections += [pscustomobject]@{
                    DetectionId               = 'MFA-DET-005'
                    UserPrincipalName         = $group.Name
                    PreviousCountry           = $prevCountry
                    CurrentCountry            = $currCountry
                    PreviousTimestamp         = $previous.CreatedDateTime
                    CurrentTimestamp          = $current.CreatedDateTime
                    TimeDeltaMinutes          = $minutes
                    PreviousResult            = $previous.Result
                    CurrentResult             = $current.Result
                    PreviousIpAddress         = $previous.IpAddress
                    CurrentIpAddress          = $current.IpAddress
                    AuthenticationRequirement = $current.AuthenticationRequirement
                    AuthenticationMethods     = $current.AuthenticationMethods
                    Severity                  = 'High'
                    Source                    = 'Get-MfaEntraSignIn'
                    FrameworkTags             = $metadata.FrameworkTags
                    NistFunctions             = $metadata.NistFunctions
                    ReportingTags             = $metadata.ReportingTags
                    ControlOwner              = $metadata.ControlOwner
                    ResponseSlaHours          = $metadata.ResponseSlaHours
                    ReviewCadenceDays         = $metadata.ReviewCadenceDays
                }

                $detected = $true
                break
            }
        }
    }

    return $detections | Sort-Object -Property UserPrincipalName
}

function Invoke-MfaSuspiciousActivityScore {
    [CmdletBinding()]
    param(
        [psobject[]] $SignInData,
        [psobject[]] $RegistrationData,
        [int] $ObservationHours = 24,
        [datetime] $ReferenceTime = (Get-Date),
        [int] $FailureThreshold = 3,
        [int] $FailureWindowMinutes = 30,
        [int] $TravelWindowMinutes = 120,
        [int] $RecentRegistrationDays = 7,
        [string[]] $WeakMethodTypes = @(
            'phoneAuthenticationMethod',
            'temporaryAccessPassAuthenticationMethod',
            'smsAuthenticationMethod',
            'voiceAuthenticationMethod'
        )
    )

    $effectiveObservationHours = $ObservationHours
    $effectiveFailureThreshold = $FailureThreshold
    $effectiveFailureWindowMinutes = $FailureWindowMinutes
    $effectiveTravelWindowMinutes = $TravelWindowMinutes
    $effectiveRecentRegistrationDays = $RecentRegistrationDays
    $effectiveWeakMethodTypes = @($WeakMethodTypes)

    $useConfig = @(
        -not $PSBoundParameters.ContainsKey('ObservationHours'),
        -not $PSBoundParameters.ContainsKey('FailureThreshold'),
        -not $PSBoundParameters.ContainsKey('FailureWindowMinutes'),
        -not $PSBoundParameters.ContainsKey('TravelWindowMinutes'),
        -not $PSBoundParameters.ContainsKey('RecentRegistrationDays'),
        -not $PSBoundParameters.ContainsKey('WeakMethodTypes')
    ) -contains $true

    if ($useConfig) {
        $config = Get-MfaDetectionConfiguration -DetectionId 'MFA-SCORE'
        if ($config) {
            if (-not $PSBoundParameters.ContainsKey('ObservationHours') -and $config.PSObject.Properties.Name -contains 'ObservationHours' -and $config.ObservationHours) {
                $effectiveObservationHours = [math]::Max(1, [int]$config.ObservationHours)
            }
            if (-not $PSBoundParameters.ContainsKey('FailureThreshold') -and $config.PSObject.Properties.Name -contains 'FailureThreshold' -and $config.FailureThreshold) {
                $effectiveFailureThreshold = [math]::Max(1, [int]$config.FailureThreshold)
            }
            if (-not $PSBoundParameters.ContainsKey('FailureWindowMinutes') -and $config.PSObject.Properties.Name -contains 'FailureWindowMinutes' -and $config.FailureWindowMinutes) {
                $effectiveFailureWindowMinutes = [math]::Max(1, [int]$config.FailureWindowMinutes)
            }
            if (-not $PSBoundParameters.ContainsKey('TravelWindowMinutes') -and $config.PSObject.Properties.Name -contains 'TravelWindowMinutes' -and $config.TravelWindowMinutes) {
                $effectiveTravelWindowMinutes = [math]::Max(1, [int]$config.TravelWindowMinutes)
            }
            if (-not $PSBoundParameters.ContainsKey('RecentRegistrationDays') -and $config.PSObject.Properties.Name -contains 'RecentRegistrationDays' -and $config.RecentRegistrationDays) {
                $effectiveRecentRegistrationDays = [math]::Max(1, [int]$config.RecentRegistrationDays)
            }
            if (-not $PSBoundParameters.ContainsKey('WeakMethodTypes') -and $config.PSObject.Properties.Name -contains 'WeakMethodTypes' -and $config.WeakMethodTypes) {
                $effectiveWeakMethodTypes = @($config.WeakMethodTypes)
            }
        }
    }

    $weights = @{
        ImpossibleTravel      = 40
        RepeatedFailures      = 20
        UnusualDevice         = 15
        HighRiskFactorChange  = 25
    }

    $observationHours = [math]::Abs($effectiveObservationHours)
    if ($observationHours -eq 0) {
        $observationHours = 24
    }

    $windowEnd = $ReferenceTime
    $windowStart = $ReferenceTime.AddHours(-$observationHours)

    if (-not $SignInData) {
        Write-Verbose "Fetching normalized sign-in data for the past $observationHours hour(s)."
        $SignInData = Get-MfaEntraSignIn -Normalize -StartTime $windowStart -EndTime $windowEnd
    }

    if (-not $SignInData) {
        Write-Verbose 'No sign-in data available for scoring.'
        return @()
    }

    $normalizedSignIns = foreach ($record in $SignInData) {
        if (-not $record) { continue }
        $user = $record.UserPrincipalName
        if (-not $user) { continue }

        $created = ConvertTo-MfaDateTime -Value $record.CreatedDateTime
        if (-not $created) { continue }
        if ($created -lt $windowStart -or $created -gt $windowEnd) { continue }

        [pscustomobject]@{
            Raw                      = $record
            UserPrincipalName        = $user
            CreatedDateTime          = $created
            LocationCountryOrRegion  = $record.LocationCountryOrRegion
            LocationCity             = $record.LocationCity
            Result                   = $record.Result
            RiskDetail               = $record.RiskDetail
            RiskState                = $record.RiskState
            ResultFailureReason      = $record.ResultFailureReason
            ResultAdditionalDetails  = $record.ResultAdditionalDetails
        }
    }

    if (-not $normalizedSignIns) {
        Write-Verbose 'No sign-in records fell within the observation window.'
        return @()
    }

    if (-not $RegistrationData) {
        if (Test-MfaGraphPrerequisite) {
            $uniqueUsers = $normalizedSignIns.UserPrincipalName | Sort-Object -Unique
            $collected = @()
            foreach ($user in $uniqueUsers) {
                try {
                    Write-Verbose "Fetching registration data for $user."
                    $records = Get-MfaEntraRegistration -UserId $user -Normalize
                    if ($records) {
                        $collected += $records
                    }
                }
                catch {
                    Write-Verbose "Failed to load registration data for ${user}: $($_.Exception.Message)"
                }
            }
            if ($collected) {
                $RegistrationData = $collected
            }
        }
        else {
            Write-Verbose 'Microsoft.Graph module not detected; skipping registration lookup.'
        }
    }

    $registrationsByUser = @{}
    foreach ($registration in ($RegistrationData | Where-Object { $_ })) {
        $user = $registration.UserPrincipalName
        if (-not $user) { continue }
        if (-not $registrationsByUser.ContainsKey($user)) {
            $registrationsByUser[$user] = @()
        }
        $registrationsByUser[$user] += $registration
    }

    $failureWindow = [TimeSpan]::FromMinutes([math]::Abs($effectiveFailureWindowMinutes))
    if ($failureWindow.TotalMinutes -eq 0) {
        $failureWindow = [TimeSpan]::FromMinutes(1)
    }

    $travelWindow = [TimeSpan]::FromMinutes([math]::Abs($effectiveTravelWindowMinutes))
    if ($travelWindow.TotalMinutes -eq 0) {
        $travelWindow = [TimeSpan]::FromMinutes(120)
    }

    $recentRegistrationCutoff = $windowEnd.AddDays(-[math]::Abs($effectiveRecentRegistrationDays))
    $weakMethodSet = [System.Collections.Generic.HashSet[string]]::new([string[]]$effectiveWeakMethodTypes)
    $unusualRiskDetails = @('unfamiliarFeaturesOfThisDevice', 'newDevice', 'registerSecurityInformation')

    $results = @()
    $signInsByUser = $normalizedSignIns | Group-Object -Property UserPrincipalName
    foreach ($group in $signInsByUser) {
        $user = $group.Name
        $records = $group.Group | Sort-Object -Property CreatedDateTime
        $indicators = @()

        # Impossible travel detection
        for ($i = 1; $i -lt $records.Count; $i++) {
            $previous = $records[$i - 1]
            $current = $records[$i]
            $prevCountry = $previous.LocationCountryOrRegion
            $currCountry = $current.LocationCountryOrRegion
            if (-not $prevCountry -or -not $currCountry) { continue }
            if ($prevCountry -eq $currCountry) { continue }

            $delta = $current.CreatedDateTime - $previous.CreatedDateTime
            if ([math]::Abs($delta.TotalMinutes) -le $travelWindow.TotalMinutes) {
                $detail = "Country changed from $prevCountry to $currCountry within {0} minute(s)." -f [math]::Round([math]::Abs($delta.TotalMinutes), 0)
                $indicators += [pscustomobject]@{
                    Type      = 'ImpossibleTravel'
                    Weight    = $weights.ImpossibleTravel
                    Details   = $detail
                    Timestamp = $current.CreatedDateTime
                }
                break
            }
        }

        # Repeated failures detection
        $failureRecords = $records | Where-Object { $_.Result -eq 'Failure' }
        $failureCount = @($failureRecords).Count
        if ($failureCount -ge $effectiveFailureThreshold) {
            $queue = [System.Collections.Generic.Queue[datetime]]::new()
            $trigger = $null
            foreach ($failure in ($failureRecords | Sort-Object -Property CreatedDateTime)) {
                while ($queue.Count -gt 0 -and ($failure.CreatedDateTime - $queue.Peek()) -gt $failureWindow) {
                    [void]$queue.Dequeue()
                }
                $queue.Enqueue($failure.CreatedDateTime)
                if (-not $trigger -and $queue.Count -ge $effectiveFailureThreshold) {
                    $trigger = @{
                        Start = $queue.Peek()
                        End   = $failure.CreatedDateTime
                        Count = $queue.Count
                    }
                }
            }

            if ($trigger) {
                $detail = "{0} failures between {1:o} and {2:o}." -f $trigger.Count, $trigger.Start, $trigger.End
                $indicators += [pscustomobject]@{
                    Type      = 'RepeatedFailures'
                    Weight    = $weights.RepeatedFailures
                    Details   = $detail
                    Timestamp = $trigger.End
                }
            }
        }

        # Unusual device detection
        $unusualRecord = $records | Where-Object {
            ($_.RiskDetail -and ($unusualRiskDetails -contains $_.RiskDetail)) -or
            ($_.ResultFailureReason -and ($_.ResultFailureReason -match 'device')) -or
            ($_.ResultAdditionalDetails -and ($_.ResultAdditionalDetails -match 'device'))
        } | Select-Object -First 1

        if ($unusualRecord) {
            $detail = "Risk detail '{0}' observed with result '{1}'.".Trim() -f $unusualRecord.RiskDetail, $unusualRecord.Result
            $indicators += [pscustomobject]@{
                Type      = 'UnusualDevice'
                Weight    = $weights.UnusualDevice
                Details   = $detail
                Timestamp = $unusualRecord.CreatedDateTime
            }
        }

        # High-risk factor change detection
        if ($registrationsByUser.ContainsKey($user)) {
            $userRegistrations = $registrationsByUser[$user]
            $recentWeakMethod = $userRegistrations | Where-Object {
                $_.IsDefault -eq $true -and
                $_.MethodType -and
                $weakMethodSet.Contains([string]$_.MethodType) -and
                (ConvertTo-MfaDateTime -Value $_.LastUpdatedDateTime) -ge $recentRegistrationCutoff
            } | Select-Object -First 1

            if ($recentWeakMethod) {
                $lastUpdated = ConvertTo-MfaDateTime -Value $recentWeakMethod.LastUpdatedDateTime
                $detail = "Default method set to {0} on {1:o}." -f $recentWeakMethod.MethodType, $lastUpdated
                $indicators += [pscustomobject]@{
                    Type      = 'HighRiskFactorChange'
                    Weight    = $weights.HighRiskFactorChange
                    Details   = $detail
                    Timestamp = $lastUpdated
                }
            }
        }

        if (-not $indicators) { continue }

        $score = ($indicators | Measure-Object -Property Weight -Sum).Sum
        $severity = 'Informational'
        if ($score -ge 75) {
            $severity = 'Critical'
        }
        elseif ($score -ge 50) {
            $severity = 'High'
        }
        elseif ($score -ge 25) {
            $severity = 'Medium'
        }

        $metadata = Resolve-MfaDetectionMetadata -DetectionId 'MFA-SCORE' -Severity $severity

        $results += [pscustomobject]@{
            UserPrincipalName = $user
            Score             = $score
            Severity          = $severity
            Indicators        = $indicators
            WindowStart       = $windowStart
            WindowEnd         = $windowEnd
            SignInCount       = $records.Count
            FailureCount      = $failureCount
            SignalId          = 'MFA-SCORE'
            FrameworkTags     = $metadata.FrameworkTags
            NistFunctions     = $metadata.NistFunctions
            ReportingTags     = $metadata.ReportingTags
            ControlOwner      = $metadata.ControlOwner
            ResponseSlaHours  = $metadata.ResponseSlaHours
            ReviewCadenceDays = $metadata.ReviewCadenceDays
        }
    }

    return $results | Sort-Object -Property Score -Descending
}

function Invoke-MfaDetectionPrivilegedRoleNoMfa {
    [CmdletBinding()]
    param(
        [psobject[]] $RoleAssignments,
        [psobject[]] $RegistrationData,
        [string[]] $PrivilegedRoleIds,
        [switch] $IncludeDisabledMethods
    )

    $effectiveRoleIds = $PrivilegedRoleIds
    if (-not $PSBoundParameters.ContainsKey('PrivilegedRoleIds')) {
        $config = Get-MfaDetectionConfiguration -DetectionId 'MFA-DET-003'
        if ($config -and $config.PSObject.Properties['PrivilegedRoleIds']) {
            $effectiveRoleIds = @($config.PrivilegedRoleIds)
        }
    }
    if (-not $effectiveRoleIds) {
        $effectiveRoleIds = @(
            '62e90394-69f5-4237-9190-012177145e10',
            'e8611ab8-c189-46e8-94e1-60213ab1f814',
            '194ae4cb-b126-40b2-bd5b-6091b380977d',
            'b0f54661-2d74-4c50-afa3-1ec803f12efe'
        )
    }

    if (-not $RoleAssignments) {
        Write-Warning 'Role assignments not provided. Supply -RoleAssignments or extend the function to retrieve assignments from Microsoft Graph.'
        return @()
    }

    $privilegedAssignments = @($RoleAssignments | Where-Object {
        $_ -and $_.RoleDefinitionId -and ($effectiveRoleIds -contains ([string]$_.RoleDefinitionId))
    })

    if (-not $privilegedAssignments) {
        return @()
    }

    $registrationCache = @{}
    if ($RegistrationData) {
        foreach ($entry in ($RegistrationData | Where-Object { $_ })) {
            $identifier = if ($entry.UserId) { [string]$entry.UserId } elseif ($entry.UserPrincipalName) { [string]$entry.UserPrincipalName } else { $null }
            if (-not $identifier) { continue }
            if (-not $registrationCache.ContainsKey($identifier)) {
                $registrationCache[$identifier] = @()
            }
            $registrationCache[$identifier] += $entry
        }
    }

    $results = @()
    $groupedAssignments = $privilegedAssignments | Group-Object -Property {
        if ($_.PrincipalId) { [string]$_.PrincipalId } else { [string]$_.UserId }
    }

    foreach ($group in $groupedAssignments) {
        $principalId = $group.Name
        if (-not $principalId) { continue }
        $assignments = $group.Group
        $roleNames = ($assignments | ForEach-Object {
            if ($_.RoleDefinitionDisplayName) { [string]$_.RoleDefinitionDisplayName }
            elseif ($_.RoleDefinitionName) { [string]$_.RoleDefinitionName }
            else { [string]$_.RoleDefinitionId }
        }) | Sort-Object -Unique

        $upn = $null
        $displayName = $null
        foreach ($assignment in $assignments) {
            if (-not $upn -and $assignment.PSObject.Properties['UserPrincipalName']) {
                $upn = [string]$assignment.UserPrincipalName
            }
            if (-not $displayName -and $assignment.PSObject.Properties['UserDisplayName']) {
                $displayName = [string]$assignment.UserDisplayName
            }
        }

        $registrations = $null
        if ($registrationCache.ContainsKey($principalId)) {
            $registrations = $registrationCache[$principalId]
        }
        elseif ($upn -and $registrationCache.ContainsKey($upn)) {
            $registrations = $registrationCache[$upn]
        }
        elseif (-not $RegistrationData -and (Test-MfaGraphPrerequisite)) {
            try {
                $fetched = $null
                if ($upn) {
                    $fetched = Get-MfaEntraRegistration -UserId $upn -Normalize
                }
                elseif ($principalId) {
                    $fetched = Get-MfaEntraRegistration -UserId $principalId -Normalize
                }
                if ($fetched) {
                    $registrationCache[$principalId] = $fetched
                    $registrations = $fetched
                }
            }
            catch {
                Write-Verbose "Failed to retrieve registration data for ${principalId}: $($_.Exception.Message)"
            }
        }

        $hasUsableMfa = $false
        if ($registrations) {
            foreach ($entry in $registrations) {
                $usable = $entry.IsUsable
                if ($IncludeDisabledMethods) {
                    if ($usable -ne $false) {
                        $hasUsableMfa = $true
                        break
                    }
                }
                else {
                    if ($usable -eq $true -or $usable -eq $null) {
                        $hasUsableMfa = $true
                        break
                    }
                }
            }
        }

        if (-not $hasUsableMfa) {
            $metadata = Resolve-MfaDetectionMetadata -DetectionId 'MFA-DET-003' -Severity 'Critical'
            $results += [pscustomobject]@{
                DetectionId          = 'MFA-DET-003'
                UserPrincipalName    = $upn
                UserDisplayName      = $displayName
                PrincipalId          = $principalId
                PrivilegedRoles      = $roleNames
                RegistrationCount    = if ($registrations) { $registrations.Count } else { 0 }
                Severity             = 'Critical'
                Source               = 'RoleAssignments'
                FrameworkTags        = $metadata.FrameworkTags
                NistFunctions        = $metadata.NistFunctions
                ReportingTags        = $metadata.ReportingTags
                ControlOwner         = $metadata.ControlOwner
                ResponseSlaHours     = $metadata.ResponseSlaHours
                ReviewCadenceDays    = $metadata.ReviewCadenceDays
            }
        }
    }

    return $results | Sort-Object -Property UserPrincipalName
}

function Invoke-MfaPlaybookResetDormantMethod {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [psobject] $Detection,

        [switch] $SkipAuthorization,
        [switch] $SkipGraphValidation,
        [switch] $NoUserNotification
    )

    begin {
        if (-not $SkipAuthorization) {
            Test-MfaPlaybookAuthorization -PlaybookId 'MFA-PL-001' | Out-Null
        }
        $results = @()
    }

    process {
        if (-not $Detection) {
            throw "Detection input is required. Pipe the object emitted by Invoke-MfaDetectionDormantMethod or specify -Detection."
        }

        $detectionId = if ($Detection.PSObject.Properties['DetectionId']) { [string]$Detection.DetectionId } else { $null }
        if ($detectionId -and $detectionId -ne 'MFA-DET-001') {
            Write-Warning ("Playbook MFA-PL-001 targets detection 'MFA-DET-001'. Input '{0}' may not be compatible." -f $detectionId)
        }

        $user = if ($Detection.PSObject.Properties['UserPrincipalName']) { [string]$Detection.UserPrincipalName } else { $null }
        if (-not $user) {
            throw "Detection input does not include 'UserPrincipalName'. Cannot proceed."
        }

        $methodType = if ($Detection.PSObject.Properties['MethodType']) { [string]$Detection.MethodType } else { $null }
        $severity = if ($Detection.PSObject.Properties['Severity'] -and $Detection.Severity) { [string]$Detection.Severity } else { 'Medium' }
        $metadata = Resolve-MfaDetectionMetadata -DetectionId 'MFA-DET-001' -Severity $severity

        if (-not $SkipGraphValidation) {
            $context = Get-MfaGraphContext
            if (-not $context) {
                throw "Microsoft Graph context not found. Run Connect-MfaGraphDeviceCode or use -SkipGraphValidation to bypass this check."
            }
        }

        $steps = @(
            @{ Step = 'Notify user'; Description = "Notify $user and relevant SecOps queues about the upcoming MFA reset."; Key = 'NotifyUser' },
            @{ Step = 'Disable stale method'; Description = "Disable or remove the dormant method ($methodType) via Microsoft Graph."; Key = 'DisableMethod' },
            @{ Step = 'Trigger re-registration'; Description = "Send MFA re-registration instructions and schedule follow-up."; Key = 'TriggerReregistration' },
            @{ Step = 'Update ticket'; Description = "Update the incident/ticket with remediation evidence and SLA status."; Key = 'UpdateTicket' }
        )

        $executedSteps = @()
        $isSimulation = ($WhatIfPreference -eq $true)
        $stepNumber = 0

        foreach ($step in $steps) {
            $stepNumber++
            $action = "{0}/{1}: {2}" -f $stepNumber, $steps.Count, $step.Description
            $shouldProcess = $PSCmdlet.ShouldProcess($user, $step.Step)
            if ($shouldProcess -or $isSimulation) {
                if ($isSimulation) {
                    Write-Verbose ("[SIMULATION] {0}" -f $action)
                }
                elseif ($shouldProcess) {
                    Write-Host ("Step {0}" -f $action) -ForegroundColor Cyan
                    switch ($step.Key) {
                        'NotifyUser' {
                            if (-not $NoUserNotification) {
                                Write-Verbose ("Prepare notification template for {0} referencing detection {1}." -f $user, $detectionId)
                            }
                            else {
                                Write-Verbose 'User notification suppressed by -NoUserNotification.'
                            }
                        }
                        'DisableMethod' {
                            Write-Verbose 'Call Microsoft Graph (e.g., Remove-MgUserAuthenticationPhoneMethod) to revoke the stale method.'
                        }
                        'TriggerReregistration' {
                            Write-Verbose 'Send Secure MFA re-registration link or schedule live re-proofing session.'
                        }
                        'UpdateTicket' {
                            Write-Verbose 'Update ticketing/ITSM system with remediation details and SLA compliance.'
                        }
                    }
                }

                $executedSteps += $step.Step
            }
        }

        $results += [pscustomobject]@{
            PlaybookId        = 'MFA-PL-001'
            DetectionId       = $detectionId
            UserPrincipalName = $user
            MethodType        = $methodType
            ExecutedSteps     = $executedSteps
            IsSimulation      = $isSimulation
            GraphValidated    = (-not $SkipGraphValidation)
            NotificationsSent = (-not $NoUserNotification)
            ControlOwner      = $metadata.ControlOwner
            ResponseSlaHours  = $metadata.ResponseSlaHours
            ReviewCadenceDays = $metadata.ReviewCadenceDays
        }
    }

    end {
        return $results
    }
}

function Invoke-MfaPlaybookEnforcePrivilegedRoleMfa {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [psobject] $Detection,

        [switch] $SkipAuthorization,
        [switch] $SkipGraphValidation,
        [switch] $NoUserNotification,
        [switch] $NoTicketUpdate
    )

    begin {
        if (-not $SkipAuthorization) {
            Test-MfaPlaybookAuthorization -PlaybookId 'MFA-PL-003' | Out-Null
        }
        $results = @()
    }

    process {
        if (-not $Detection) {
            throw "Detection input is required. Pipe the object emitted by MFA-DET-003 once implemented or specify -Detection."
        }

        $detectionId = if ($Detection.PSObject.Properties['DetectionId']) { [string]$Detection.DetectionId } else { $null }
        if ($detectionId -and $detectionId -ne 'MFA-DET-003') {
            Write-Warning ("Playbook MFA-PL-003 targets detection 'MFA-DET-003'. Input '{0}' may not be compatible." -f $detectionId)
        }

        $user = if ($Detection.PSObject.Properties['UserPrincipalName']) { [string]$Detection.UserPrincipalName } else { $null }
        if (-not $user) {
            throw "Detection input does not include 'UserPrincipalName'. Cannot proceed."
        }

        $privilegedRoles = @()
        if ($Detection.PSObject.Properties['PrivilegedRoles']) {
            $privilegedRoles = @($Detection.PrivilegedRoles | Where-Object { $_ })
        }
        elseif ($Detection.PSObject.Properties['Roles']) {
            $privilegedRoles = @($Detection.Roles | Where-Object { $_ })
        }

        $severity = if ($Detection.PSObject.Properties['Severity'] -and $Detection.Severity) { [string]$Detection.Severity } else { 'High' }
        $metadata = Resolve-MfaDetectionMetadata -DetectionId 'MFA-DET-003' -Severity $severity

        if (-not $SkipGraphValidation) {
            $context = Get-MfaGraphContext
            if (-not $context) {
                throw "Microsoft Graph context not found. Run Connect-MfaGraphDeviceCode or use -SkipGraphValidation to bypass this check."
            }
        }

        $steps = @(
            @{
                Step = 'Review role assignments'
                Description = "Review privileged role membership for $user and confirm necessity."
                Key = 'ReviewRoles'
            },
            @{
                Step = 'Assess exemptions'
                Description = "Check for approved MFA exemptions or break-glass status."
                Key = 'AssessExemptions'
            },
            @{
                Step = 'Enable MFA enforcement'
                Description = "Apply or re-enable MFA enforcement, adding compliant factors."
                Key = 'EnableMfa'
            },
            @{
                Step = 'Validate conditional access'
                Description = "Ensure conditional access policies cover $user and privileged roles."
                Key = 'ValidateCA'
            },
            @{
                Step = 'Notify stakeholders'
                Description = "Inform the user and IAM governance of the change."
                Key = 'NotifyStakeholders'
                Skip = { $NoUserNotification }
            },
            @{
                Step = 'Update ticket'
                Description = "Document remediation actions and schedule follow-up verification."
                Key = 'UpdateTicket'
                Skip = { $NoTicketUpdate }
            }
        )

        $executedSteps = @()
        $skippedSteps = @()
        $isSimulation = ($WhatIfPreference -eq $true)
        $stepNumber = 0

        foreach ($step in $steps) {
            $stepNumber++
            $skipFn = $step['Skip']
            if ($skipFn -and (& $skipFn)) {
                Write-Verbose ("Skipping step '{0}' per operator preference." -f $step.Step)
                $skippedSteps += $step.Step
                continue
            }

            $action = "{0}/{1}: {2}" -f $stepNumber, $steps.Count, $step.Description
            $shouldProcess = $PSCmdlet.ShouldProcess($user, $step.Step)
            if ($shouldProcess -or $isSimulation) {
                if ($isSimulation) {
                    Write-Verbose ("[SIMULATION] {0}" -f $action)
                }
                elseif ($shouldProcess) {
                    Write-Host ("Step {0}" -f $action) -ForegroundColor Cyan
                    switch ($step.Key) {
                        'ReviewRoles' {
                            Write-Verbose 'Enumerate role assignments (Get-MgRoleManagementDirectoryRoleAssignmentScheduleInstance).'
                        }
                        'AssessExemptions' {
                            Write-Verbose 'Check for approved exemptions or break-glass flags before making changes.'
                        }
                        'EnableMfa' {
                            Write-Verbose 'Apply MFA enforcement and seed strong methods (e.g., FIDO2, Authenticator).'
                        }
                        'ValidateCA' {
                            Write-Verbose 'Verify applicable conditional access policies include the user and privileged groups.'
                        }
                        'NotifyStakeholders' {
                            if ($NoUserNotification) {
                                Write-Verbose 'Notifications suppressed by -NoUserNotification.'
                            }
                            else {
                                Write-Verbose 'Notify user, IAM governance, and change-management queue.'
                            }
                        }
                        'UpdateTicket' {
                            if ($NoTicketUpdate) {
                                Write-Verbose 'Ticket updates suppressed by -NoTicketUpdate.'
                            }
                            else {
                                Write-Verbose 'Update ticketing/ITSM system with remediation evidence.'
                            }
                        }
                    }
                }

                $executedSteps += $step.Step
            }
        }

        $results += [pscustomobject]@{
            PlaybookId        = 'MFA-PL-003'
            DetectionId       = $detectionId
            UserPrincipalName = $user
            PrivilegedRoles   = $privilegedRoles
            ExecutedSteps     = $executedSteps
            SkippedSteps      = $skippedSteps
            IsSimulation      = $isSimulation
            GraphValidated    = (-not $SkipGraphValidation)
            NotificationsSent = (-not $NoUserNotification)
            TicketUpdated     = (-not $NoTicketUpdate)
            ControlOwner      = $metadata.ControlOwner
            ResponseSlaHours  = $metadata.ResponseSlaHours
            ReviewCadenceDays = $metadata.ReviewCadenceDays
        }
    }

    end {
        return $results
    }
}

function Invoke-MfaPlaybookContainHighRiskSignin {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [psobject] $Detection,

        [switch] $SkipAuthorization,
        [switch] $SkipGraphValidation,
        [switch] $NoUserNotification,
        [switch] $NoTicketUpdate
    )

    begin {
        if (-not $SkipAuthorization) {
            Test-MfaPlaybookAuthorization -PlaybookId 'MFA-PL-002' | Out-Null
        }
        $results = @()
    }

    process {
        if (-not $Detection) {
            throw "Detection input is required. Pipe the object emitted by Invoke-MfaDetectionHighRiskSignin or specify -Detection."
        }

        $detectionId = if ($Detection.PSObject.Properties['DetectionId']) { [string]$Detection.DetectionId } else { $null }
        if ($detectionId -and $detectionId -ne 'MFA-DET-002') {
            Write-Warning ("Playbook MFA-PL-002 targets detection 'MFA-DET-002'. Input '{0}' may not be compatible." -f $detectionId)
        }

        $user = if ($Detection.PSObject.Properties['UserPrincipalName']) { [string]$Detection.UserPrincipalName } else { $null }
        if (-not $user) {
            throw "Detection input does not include 'UserPrincipalName'. Cannot proceed."
        }

        $correlationId = if ($Detection.PSObject.Properties['CorrelationId']) { [string]$Detection.CorrelationId } else { $null }
        $riskState = if ($Detection.PSObject.Properties['RiskState']) { [string]$Detection.RiskState } else { $null }
        $riskDetail = if ($Detection.PSObject.Properties['RiskDetail']) { [string]$Detection.RiskDetail } else { $null }
        $severity = if ($Detection.PSObject.Properties['Severity'] -and $Detection.Severity) { [string]$Detection.Severity } else { 'High' }
        $metadata = Resolve-MfaDetectionMetadata -DetectionId 'MFA-DET-002' -Severity $severity

        if (-not $SkipGraphValidation) {
            $context = Get-MfaGraphContext
            if (-not $context) {
                throw "Microsoft Graph context not found. Run Connect-MfaGraphDeviceCode or use -SkipGraphValidation to bypass this check."
            }
        }

        $steps = @(
            @{
                Step = 'Revoke sessions'
                Description = "Revoke refresh tokens and active sessions for $user (e.g., Revoke-MgUserSignInSession)."
                Key = 'RevokeSessions'
            },
            @{
                Step = 'Force password reset'
                Description = "Initiate secure password reset and flag account for review."
                Key = 'ForcePasswordReset'
            },
            @{
                Step = 'Require MFA re-registration'
                Description = "Coordinate or trigger MFA factor reset to ensure trusted methods only."
                Key = 'RequireReregistration'
            },
            @{
                Step = 'Notify stakeholders'
                Description = "Notify the user, SecOps bridge, and incident commander about containment actions."
                Key = 'NotifyStakeholders'
                Skip = { $NoUserNotification }
            },
            @{
                Step = 'Update incident/ticket'
                Description = "Update the incident record with actions, timestamps, and next steps."
                Key = 'UpdateTicket'
                Skip = { $NoTicketUpdate }
            }
        )

        $executedSteps = @()
        $skippedSteps = @()
        $isSimulation = ($WhatIfPreference -eq $true)
        $stepNumber = 0

        foreach ($step in $steps) {
            $stepNumber++
            $skipFn = $step['Skip']
            if ($skipFn -and (& $skipFn)) {
                Write-Verbose ("Skipping step '{0}' per operator preference." -f $step.Step)
                $skippedSteps += $step.Step
                continue
            }

            $action = "{0}/{1}: {2}" -f $stepNumber, $steps.Count, $step.Description
            $shouldProcess = $PSCmdlet.ShouldProcess($user, $step.Step)
            if ($shouldProcess -or $isSimulation) {
                if ($isSimulation) {
                    Write-Verbose ("[SIMULATION] {0}" -f $action)
                }
                elseif ($shouldProcess) {
                    Write-Host ("Step {0}" -f $action) -ForegroundColor Cyan
                    switch ($step.Key) {
                        'RevokeSessions' {
                            Write-Verbose 'Call Microsoft Graph to revoke active sessions (e.g., Revoke-MgUserSignInSession).'
                        }
                        'ForcePasswordReset' {
                            Write-Verbose 'Trigger secure password reset (Set-MgUser -ForceChangePasswordNextSignIn:$true) and coordinate follow-up.'
                        }
                        'RequireReregistration' {
                            Write-Verbose 'Initiate MFA re-proofing by invoking MFA reset routines or coordinating with IAM.'
                        }
                        'NotifyStakeholders' {
                            if ($NoUserNotification) {
                                Write-Verbose 'Notifications suppressed by -NoUserNotification.'
                            }
                            else {
                                Write-Verbose 'Send alert to affected user, SecOps bridge, and incident commander.'
                            }
                        }
                        'UpdateTicket' {
                            if ($NoTicketUpdate) {
                                Write-Verbose 'Ticket updates suppressed by -NoTicketUpdate.'
                            }
                            else {
                                Write-Verbose 'Update incident/ticket with containment summary, timestamps, and SLA checks.'
                            }
                        }
                    }
                }

                $executedSteps += $step.Step
            }
        }

        $results += [pscustomobject]@{
            PlaybookId        = 'MFA-PL-002'
            DetectionId       = $detectionId
            UserPrincipalName = $user
            CorrelationId     = $correlationId
            RiskState         = $riskState
            RiskDetail        = $riskDetail
            ExecutedSteps     = $executedSteps
            SkippedSteps      = $skippedSteps
            IsSimulation      = $isSimulation
            GraphValidated    = (-not $SkipGraphValidation)
            NotificationsSent = (-not $NoUserNotification)
            TicketUpdated     = (-not $NoTicketUpdate)
            ControlOwner      = $metadata.ControlOwner
            ResponseSlaHours  = $metadata.ResponseSlaHours
            ReviewCadenceDays = $metadata.ReviewCadenceDays
        }
    }

    end {
        return $results
    }
}

function Invoke-MfaPlaybookContainRepeatedFailure {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [psobject] $Detection,

        [switch] $SkipAuthorization,
        [switch] $SkipGraphValidation,
        [switch] $NoUserNotification,
        [switch] $NoTicketUpdate,
        [switch] $NoUserBlock
    )

    begin {
        if (-not $SkipAuthorization) {
            Test-MfaPlaybookAuthorization -PlaybookId 'MFA-PL-005' | Out-Null
        }
        $results = @()
    }

    process {
        if (-not $Detection) {
            throw "Detection input is required. Pipe the object emitted by Invoke-MfaDetectionRepeatedMfaFailure or specify -Detection."
        }

        $detectionId = if ($Detection.PSObject.Properties['DetectionId']) { [string]$Detection.DetectionId } else { $null }
        if ($detectionId -and $detectionId -ne 'MFA-DET-004') {
            Write-Warning ("Playbook MFA-PL-005 targets detection 'MFA-DET-004'. Input '{0}' may not be compatible." -f $detectionId)
        }

        $user = if ($Detection.PSObject.Properties['UserPrincipalName']) { [string]$Detection.UserPrincipalName } else { $null }
        if (-not $user) {
            throw "Detection input does not include 'UserPrincipalName'. Cannot proceed."
        }

        $failureCount = if ($Detection.PSObject.Properties['FailureCount']) { [int]$Detection.FailureCount } else { $null }
        $windowStart = if ($Detection.PSObject.Properties['WindowStart']) { ConvertTo-MfaDateTime -Value $Detection.WindowStart } else { $null }
        $windowEnd = if ($Detection.PSObject.Properties['WindowEnd']) { ConvertTo-MfaDateTime -Value $Detection.WindowEnd } else { $null }
        $failureWindowMinutes = if ($Detection.PSObject.Properties['FailureWindowMinutes']) { [int]$Detection.FailureWindowMinutes } else { $null }
        $failureReasons = if ($Detection.PSObject.Properties['FailureReasons']) { [string]$Detection.FailureReasons } else { $null }
        $failureErrorCodes = if ($Detection.PSObject.Properties['FailureErrorCodes']) { $Detection.FailureErrorCodes } else { $null }
        $correlationIds = if ($Detection.PSObject.Properties['CorrelationIds']) { $Detection.CorrelationIds } else { $null }

        $severity = if ($Detection.PSObject.Properties['Severity'] -and $Detection.Severity) { [string]$Detection.Severity } else { 'Medium' }
        $metadata = Resolve-MfaDetectionMetadata -DetectionId 'MFA-DET-004' -Severity $severity

        if (-not $SkipGraphValidation) {
            $context = Get-MfaGraphContext
            if (-not $context) {
                throw "Microsoft Graph context not found. Run Connect-MfaGraphDeviceCode or use -SkipGraphValidation to bypass this check."
            }
        }

        $steps = @(
            @{
                Step = 'Contact user'
                Description = "Engage $user (and manager/security contacts) to validate whether the failures were legitimate."
                Key = 'NotifyUser'
                Skip = { $NoUserNotification }
            },
            @{
                Step = 'Temporarily block sign-in'
                Description = "Apply a temporary sign-in block or require password reset for $user to halt further attempts."
                Key = 'BlockSignin'
                Skip = { $NoUserBlock }
            },
            @{
                Step = 'Reset credentials'
                Description = "Trigger secure password reset and enforce MFA re-registration with strong factors."
                Key = 'ResetCredential'
            },
            @{
                Step = 'Investigate sources'
                Description = "Review source IPs/devices, adjust conditional access, and coordinate with network defenders."
                Key = 'InvestigateSources'
            },
            @{
                Step = 'Update ticket'
                Description = "Document containment actions, SLA timestamps, and remaining tasks."
                Key = 'UpdateTicket'
                Skip = { $NoTicketUpdate }
            },
            @{
                Step = 'Monitor follow-up'
                Description = "Schedule follow-up monitoring for recurring failures or related alerts."
                Key = 'MonitorFollowUp'
            }
        )

        $executedSteps = @()
        $skippedSteps = @()
        $isSimulation = ($WhatIfPreference -eq $true)
        $stepNumber = 0

        foreach ($step in $steps) {
            $stepNumber++
            $skipFn = $step['Skip']
            if ($skipFn -and (& $skipFn)) {
                Write-Verbose ("Skipping step '{0}' per operator preference." -f $step.Step)
                $skippedSteps += $step.Step
                continue
            }

            $action = "{0}/{1}: {2}" -f $stepNumber, $steps.Count, $step.Description
            $shouldProcess = $PSCmdlet.ShouldProcess($user, $step.Step)
            if ($shouldProcess -or $isSimulation) {
                if ($isSimulation) {
                    Write-Verbose ("[SIMULATION] {0}" -f $action)
                }
                elseif ($shouldProcess) {
                    Write-Host ("Step {0}" -f $action) -ForegroundColor Cyan
                    switch ($step.Key) {
                        'NotifyUser' {
                            Write-Verbose 'Coordinate rapid user validation (call/SMS) and capture user feedback.'
                        }
                        'BlockSignin' {
                            Write-Verbose 'Apply temporary account lock or sign-in risk policy (e.g., Set-MgUser -AccountEnabled:$false) until reset completes.'
                        }
                        'ResetCredential' {
                            Write-Verbose 'Trigger secure password reset and enforce MFA re-registration via IAM processes.'
                        }
                        'InvestigateSources' {
                            Write-Verbose 'Analyze Identity Protection, Azure AD sign-in logs, and network telemetry for source IP correlation.'
                        }
                        'UpdateTicket' {
                            Write-Verbose 'Update ticket/ITSM with actions taken, IP indicators, and follow-up tasks.'
                        }
                        'MonitorFollowUp' {
                            Write-Verbose 'Queue monitoring reminder and ensure SOC dashboards track additional failures.'
                        }
                    }
                }

                $executedSteps += $step.Step
            }
        }

        $results += [pscustomobject]@{
            PlaybookId            = 'MFA-PL-005'
            DetectionId           = $detectionId
            UserPrincipalName     = $user
            FailureCount          = $failureCount
            WindowStart           = $windowStart
            WindowEnd             = $windowEnd
            FailureWindowMinutes  = $failureWindowMinutes
            FailureReasons        = $failureReasons
            FailureErrorCodes     = $failureErrorCodes
            CorrelationIds        = $correlationIds
            ExecutedSteps         = $executedSteps
            SkippedSteps          = $skippedSteps
            IsSimulation          = $isSimulation
            GraphValidated        = (-not $SkipGraphValidation)
            NotificationsSent     = (-not $NoUserNotification)
            TicketUpdated         = (-not $NoTicketUpdate)
            UserBlocked           = (-not $NoUserBlock)
            ControlOwner          = $metadata.ControlOwner
            ResponseSlaHours      = $metadata.ResponseSlaHours
            ReviewCadenceDays     = $metadata.ReviewCadenceDays
        }
    }

    end {
        return $results
    }
}

function Invoke-MfaPlaybookInvestigateImpossibleTravel {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [psobject] $Detection,

        [switch] $SkipAuthorization,
        [switch] $SkipGraphValidation,
        [switch] $NoUserNotification,
        [switch] $NoTicketUpdate,
        [switch] $NoSessionRevocation
    )

    begin {
        if (-not $SkipAuthorization) {
            Test-MfaPlaybookAuthorization -PlaybookId 'MFA-PL-006' | Out-Null
        }
        $results = @()
    }

    process {
        if (-not $Detection) {
            throw "Detection input is required. Pipe the object emitted by Invoke-MfaDetectionImpossibleTravelSuccess or specify -Detection."
        }

        $detectionId = if ($Detection.PSObject.Properties['DetectionId']) { [string]$Detection.DetectionId } else { $null }
        if ($detectionId -and $detectionId -ne 'MFA-DET-005') {
            Write-Warning ("Playbook MFA-PL-006 targets detection 'MFA-DET-005'. Input '{0}' may not be compatible." -f $detectionId)
        }

        $user = if ($Detection.PSObject.Properties['UserPrincipalName']) { [string]$Detection.UserPrincipalName } else { $null }
        if (-not $user) {
            throw "Detection input does not include 'UserPrincipalName'. Cannot proceed."
        }

        $previousCountry = if ($Detection.PSObject.Properties['PreviousCountry']) { [string]$Detection.PreviousCountry } else { $null }
        $currentCountry = if ($Detection.PSObject.Properties['CurrentCountry']) { [string]$Detection.CurrentCountry } else { $null }
        $previousTimestamp = if ($Detection.PSObject.Properties['PreviousTimestamp']) { ConvertTo-MfaDateTime -Value $Detection.PreviousTimestamp } else { $null }
        $currentTimestamp = if ($Detection.PSObject.Properties['CurrentTimestamp']) { ConvertTo-MfaDateTime -Value $Detection.CurrentTimestamp } else { $null }
        $timeDeltaMinutes = if ($Detection.PSObject.Properties['TimeDeltaMinutes']) { [int]$Detection.TimeDeltaMinutes } else { $null }
        $previousIp = if ($Detection.PSObject.Properties['PreviousIpAddress']) { [string]$Detection.PreviousIpAddress } else { $null }
        $currentIp = if ($Detection.PSObject.Properties['CurrentIpAddress']) { [string]$Detection.CurrentIpAddress } else { $null }
        $authRequirement = if ($Detection.PSObject.Properties['AuthenticationRequirement']) { [string]$Detection.AuthenticationRequirement } else { $null }
        $authMethods = if ($Detection.PSObject.Properties['AuthenticationMethods']) { [string]$Detection.AuthenticationMethods } else { $null }

        $severity = if ($Detection.PSObject.Properties['Severity'] -and $Detection.Severity) { [string]$Detection.Severity } else { 'High' }
        $metadata = Resolve-MfaDetectionMetadata -DetectionId 'MFA-DET-005' -Severity $severity

        if (-not $SkipGraphValidation) {
            $context = Get-MfaGraphContext
            if (-not $context) {
                throw "Microsoft Graph context not found. Run Connect-MfaGraphDeviceCode or use -SkipGraphValidation to bypass this check."
            }
        }

        $steps = @(
            @{
                Step = 'Validate with user'
                Description = "Contact $user (and manager/security contacts) to confirm travel or identify compromise."
                Key = 'ValidateUser'
                Skip = { $NoUserNotification }
            },
            @{
                Step = 'Revoke sessions'
                Description = "Revoke sessions and refresh tokens for $user to prevent cross-region token reuse."
                Key = 'RevokeSessions'
                Skip = { $NoSessionRevocation }
            },
            @{
                Step = 'Reset credentials'
                Description = "Force credential reset and MFA re-registration, prioritizing phishing-resistant factors."
                Key = 'ResetCredential'
            },
            @{
                Step = 'Review access policies'
                Description = "Review conditional access, named locations, and travel policies for gaps."
                Key = 'ReviewPolicies'
            },
            @{
                Step = 'Correlate device and IP telemetry'
                Description = "Cross-reference sign-in data with endpoint management/SIEM to detect compromised devices."
                Key = 'CorrelateTelemetry'
            },
            @{
                Step = 'Notify stakeholders'
                Description = "Inform threat hunting, incident response, and user leadership of findings."
                Key = 'NotifyStakeholders'
                Skip = { $NoUserNotification }
            },
            @{
                Step = 'Update ticket'
                Description = "Record investigation results, geo details, and residual risk in the incident record."
                Key = 'UpdateTicket'
                Skip = { $NoTicketUpdate }
            }
        )

        $executedSteps = @()
        $skippedSteps = @()
        $isSimulation = ($WhatIfPreference -eq $true)
        $stepNumber = 0

        foreach ($step in $steps) {
            $stepNumber++
            $skipFn = $step['Skip']
            if ($skipFn -and (& $skipFn)) {
                Write-Verbose ("Skipping step '{0}' per operator preference." -f $step.Step)
                $skippedSteps += $step.Step
                continue
            }

            $action = "{0}/{1}: {2}" -f $stepNumber, $steps.Count, $step.Description
            $shouldProcess = $PSCmdlet.ShouldProcess($user, $step.Step)
            if ($shouldProcess -or $isSimulation) {
                if ($isSimulation) {
                    Write-Verbose ("[SIMULATION] {0}" -f $action)
                }
                elseif ($shouldProcess) {
                    Write-Host ("Step {0}" -f $action) -ForegroundColor Cyan
                    switch ($step.Key) {
                        'ValidateUser' {
                            Write-Verbose 'Call or message the user (and manager) to verify travel details and recent activity.'
                        }
                        'RevokeSessions' {
                            Write-Verbose 'Revoke refresh tokens/sign-in sessions (Revoke-MgUserSignInSession) and consider Conditional Access session policies.'
                        }
                        'ResetCredential' {
                            Write-Verbose 'Initiate password reset and rotate app secrets if applicable; require MFA re-registration.'
                        }
                        'ReviewPolicies' {
                            Write-Verbose 'Inspect conditional access rules, named locations, and travel policies for missing controls.'
                        }
                        'CorrelateTelemetry' {
                            Write-Verbose 'Correlate with Defender, Sentinel, or SIEM telemetry to detect broader compromise.'
                        }
                        'NotifyStakeholders' {
                            Write-Verbose 'Notify threat hunting, incident response, and management; include geo/IP summary.'
                        }
                        'UpdateTicket' {
                            Write-Verbose 'Update incident record with investigation notes, timings, and escalations.'
                        }
                    }
                }

                $executedSteps += $step.Step
            }
        }

        $results += [pscustomobject]@{
            PlaybookId               = 'MFA-PL-006'
            DetectionId              = $detectionId
            UserPrincipalName        = $user
            PreviousCountry          = $previousCountry
            CurrentCountry           = $currentCountry
            PreviousTimestamp        = $previousTimestamp
            CurrentTimestamp         = $currentTimestamp
            TimeDeltaMinutes         = $timeDeltaMinutes
            PreviousIpAddress        = $previousIp
            CurrentIpAddress         = $currentIp
            AuthenticationRequirement = $authRequirement
            AuthenticationMethods    = $authMethods
            ExecutedSteps            = $executedSteps
            SkippedSteps             = $skippedSteps
            IsSimulation             = $isSimulation
            GraphValidated           = (-not $SkipGraphValidation)
            SessionsRevoked          = (-not $NoSessionRevocation)
            NotificationsSent        = (-not $NoUserNotification)
            TicketUpdated            = (-not $NoTicketUpdate)
            ControlOwner             = $metadata.ControlOwner
            ResponseSlaHours         = $metadata.ResponseSlaHours
            ReviewCadenceDays        = $metadata.ReviewCadenceDays
        }
    }

    end {
        return $results
    }
}

function Invoke-MfaPlaybookTriageSuspiciousScore {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [psobject] $Score,

        [switch] $SkipAuthorization,
        [switch] $NoTicketUpdate
    )

    begin {
        if (-not $SkipAuthorization) {
            Test-MfaPlaybookAuthorization -PlaybookId 'MFA-PL-004' | Out-Null
        }
        $results = @()
    }

    process {
        if (-not $Score) {
            throw "Score input is required. Pipe the object emitted by Invoke-MfaSuspiciousActivityScore or specify -Score."
        }

        $user = if ($Score.PSObject.Properties['UserPrincipalName']) { [string]$Score.UserPrincipalName } else { $null }
        if (-not $user) {
            throw "Score input does not include 'UserPrincipalName'. Cannot proceed."
        }

        $severity = if ($Score.PSObject.Properties['Severity'] -and $Score.Severity) { [string]$Score.Severity } else { 'Informational' }
        $scoreValue = if ($Score.PSObject.Properties['Score']) { [int]$Score.Score } else { 0 }
        $indicators = if ($Score.PSObject.Properties['Indicators']) { @($Score.Indicators) } else { @() }
        $metadata = Resolve-MfaDetectionMetadata -DetectionId 'MFA-SCORE' -Severity $severity

        $steps = @(
            @{
                Step = 'Review indicators'
                Description = "Review score indicators and summarize suspicious signals."
                Key = 'ReviewIndicators'
            },
            @{
                Step = 'Correlate additional signals'
                Description = 'Pull recent sign-ins, Identity Protection alerts, and related tickets.'
                Key = 'CorrelateSignals'
            },
            @{
                Step = 'Engage user or service owner'
                Description = "Contact $user or delegated owner to validate activity."
                Key = 'EngageUser'
            },
            @{
                Step = 'Decide containment'
                Description = 'Decide whether to escalate to containment playbooks or continue monitoring.'
                Key = 'DecideContainment'
            },
            @{
                Step = 'Update ticket'
                Description = 'Document triage outcome, SLA status, and next steps.'
                Key = 'UpdateTicket'
                Skip = { $NoTicketUpdate }
            }
        )

        $executedSteps = @()
        $skippedSteps = @()
        $isSimulation = ($WhatIfPreference -eq $true)
        $stepNumber = 0

        foreach ($step in $steps) {
            $stepNumber++
            $skipFn = $step['Skip']
            if ($skipFn -and (& $skipFn)) {
                Write-Verbose ("Skipping step '{0}' per operator preference." -f $step.Step)
                $skippedSteps += $step.Step
                continue
            }

            $action = "{0}/{1}: {2}" -f $stepNumber, $steps.Count, $step.Description
            $shouldProcess = $PSCmdlet.ShouldProcess($user, $step.Step)
            if ($shouldProcess -or $isSimulation) {
                if ($isSimulation) {
                    Write-Verbose ("[SIMULATION] {0}" -f $action)
                }
                elseif ($shouldProcess) {
                    Write-Host ("Step {0}" -f $action) -ForegroundColor Cyan
                    switch ($step.Key) {
                        'ReviewIndicators' {
                            Write-Verbose ("Indicators: {0}" -f ($indicators | ForEach-Object { $_.Type } -join ', '))
                        }
                        'CorrelateSignals' {
                            Write-Verbose 'Query recent sign-ins and Identity Protection risk events for additional context.'
                        }
                        'EngageUser' {
                            Write-Verbose 'Reach out to the user/service owner using secure communication channels.'
                        }
                        'DecideContainment' {
                            Write-Verbose 'Determine whether to escalate to MFA-PL-002 or continue monitoring.'
                        }
                        'UpdateTicket' {
                            if ($NoTicketUpdate) {
                                Write-Verbose 'Ticket updates suppressed by -NoTicketUpdate.'
                            }
                            else {
                                Write-Verbose 'Record triage outcome, SLA status, and recommended actions.'
                            }
                        }
                    }
                }

                $executedSteps += $step.Step
            }
        }

        $recommendedAction = 'Monitor'
        $suggestContainment = $false
        if ($severity -in @('Critical', 'High')) {
            $recommendedAction = 'Launch MFA-PL-002 containment'
            $suggestContainment = $true
        }

        $results += [pscustomobject]@{
            PlaybookId           = 'MFA-PL-004'
            SignalId             = if ($Score.PSObject.Properties['SignalId']) { $Score.SignalId } else { 'MFA-SCORE' }
            UserPrincipalName    = $user
            Score                = $scoreValue
            Severity             = $severity
            Indicators           = $indicators
            ExecutedSteps        = $executedSteps
            SkippedSteps         = $skippedSteps
            RecommendedAction    = $recommendedAction
            SuggestContainment   = $suggestContainment
            IsSimulation         = $isSimulation
            TicketUpdated        = (-not $NoTicketUpdate)
            ControlOwner         = $metadata.ControlOwner
            ResponseSlaHours     = $metadata.ResponseSlaHours
            ReviewCadenceDays    = $metadata.ReviewCadenceDays
        }
    }

    end {
        return $results
    }
}

function New-MfaTicketPayload {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [psobject] $Playbook,
        [string] $Provider = 'Generic',
        [string] $AssignmentGroup = 'SecOps-MFA',
        [string] $TicketType = 'Incident'
    )

    process {
        if (-not $Playbook) {
            return
        }

        $playbookId = if ($Playbook.PSObject.Properties['PlaybookId']) { [string]$Playbook.PlaybookId } else { 'Unknown' }
        $detectionId = if ($Playbook.PSObject.Properties['DetectionId']) { [string]$Playbook.DetectionId } else { $null }
        $user = if ($Playbook.PSObject.Properties['UserPrincipalName']) { [string]$Playbook.UserPrincipalName } else { $null }
        $severity = if ($Playbook.PSObject.Properties['Severity'] -and $Playbook.Severity) { [string]$Playbook.Severity } elseif ($Playbook.PSObject.Properties['RiskState'] -and $Playbook.RiskState) { [string]$Playbook.RiskState } else { 'Medium' }
        $controlOwner = if ($Playbook.PSObject.Properties['ControlOwner']) { [string]$Playbook.ControlOwner } else { $null }
        $sla = if ($Playbook.PSObject.Properties['ResponseSlaHours']) { [int]$Playbook.ResponseSlaHours } else { $null }

        $titleUser = if ($user) { $user } else { 'account' }
        $title = "[{0}] Playbook triggered for {1}" -f $playbookId, $titleUser

        $executedSteps = @()
        if ($Playbook.PSObject.Properties['ExecutedSteps']) {
            $executedSteps = @($Playbook.ExecutedSteps | Where-Object { $_ })
        }
        $skippedSteps = @()
        if ($Playbook.PSObject.Properties['SkippedSteps']) {
            $skippedSteps = @($Playbook.SkippedSteps | Where-Object { $_ })
        }

        $lines = @()
        $lines += "Playbook **$playbookId** executed for $titleUser."
        if ($detectionId) {
            $lines += "Detection: `$detectionId`."
        }
        $lines += "Severity: $severity."
        if ($executedSteps) {
            $lines += "Steps executed:"
            $lines += ($executedSteps | ForEach-Object { "- $_" })
        }
        if ($skippedSteps) {
            $lines += "Steps skipped:"
            $lines += ($skippedSteps | ForEach-Object { "- $_" })
        }

        if ($Playbook.PSObject.Properties['ReportingTags'] -and $Playbook.ReportingTags) {
            $lines += "Reporting tags: " + ($Playbook.ReportingTags -join ', ')
        }
        if ($Playbook.PSObject.Properties['FrameworkTags'] -and $Playbook.FrameworkTags) {
            $lines += "Framework tags: " + ($Playbook.FrameworkTags -join ', ')
        }

        $description = ($lines -join "`n")

        $metadata = @{
            GeneratedUtc    = (Get-Date).ToUniversalTime().ToString('o')
            PlaybookId      = $playbookId
            DetectionId     = $detectionId
            ReportingTags   = if ($Playbook.PSObject.Properties['ReportingTags']) { @($Playbook.ReportingTags) } else { @() }
            FrameworkTags   = if ($Playbook.PSObject.Properties['FrameworkTags']) { @($Playbook.FrameworkTags) } else { @() }
            Severity        = $severity
        }

        if ($Playbook.PSObject.Properties['CorrelationIds'] -and $Playbook.CorrelationIds) {
            $metadata['CorrelationIds'] = @($Playbook.CorrelationIds)
        }
        if ($Playbook.PSObject.Properties['FailureReasons'] -and $Playbook.FailureReasons) {
            $metadata['FailureReasons'] = $Playbook.FailureReasons
        }

        return [pscustomobject]@{
            Provider        = $Provider
            TicketType      = $TicketType
            Title           = $title
            Description     = $description
            PlaybookId      = $playbookId
            DetectionId     = $detectionId
            Severity        = $severity
            UserPrincipalName = $user
            ControlOwner    = $controlOwner
            ResponseSlaHours = $sla
            AssignmentGroup = $AssignmentGroup
            ExecutedSteps   = $executedSteps
            SkippedSteps    = $skippedSteps
            Metadata        = $metadata
        }
    }
}

function Submit-MfaPlaybookTicket {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [psobject] $Playbook,

        [string] $OutFile,
        [switch] $PassThru
    )

    begin {
        $ticketConfig = Get-MfaIntegrationConfig -Area 'Ticketing'
        $repoRoot = Split-Path -Parent $PSScriptRoot
        $results = @()
    }

    process {
        if (-not $Playbook) { return }

        $provider = if ($ticketConfig -and $ticketConfig.PSObject.Properties['Provider']) { [string]$ticketConfig.Provider } else { 'Generic' }
        $assignmentGroup = if ($ticketConfig -and $ticketConfig.PSObject.Properties['DefaultAssignmentGroup']) { [string]$ticketConfig.DefaultAssignmentGroup } else { 'SecOps-MFA' }
        $payload = New-MfaTicketPayload -Playbook $Playbook -Provider $provider -AssignmentGroup $assignmentGroup

        if (-not $payload) { return }

        $endpoint = if ($ticketConfig -and $ticketConfig.PSObject.Properties['Endpoint']) { [string]$ticketConfig.Endpoint } else { $null }
        $fallbackPath = 'tickets/outbox'
        if ($ticketConfig -and $ticketConfig.PSObject.Properties['FallbackPath'] -and $ticketConfig.FallbackPath) {
            $fallbackPath = [string]$ticketConfig.FallbackPath
        }

        $target = $OutFile
        $delivery = 'File'
        $response = $null

        if (-not $target) {
            if ($endpoint) {
                $target = $endpoint
                $delivery = 'Webhook'
            }
            else {
                $targetDir = if ([System.IO.Path]::IsPathRooted($fallbackPath)) { $fallbackPath } else { Join-Path -Path $repoRoot -ChildPath $fallbackPath }
                $target = Join-Path -Path $targetDir -ChildPath ("ticket-{0}.json" -f ([guid]::NewGuid()))
            }
        }

        if ($delivery -eq 'File') {
            $targetDir = Split-Path -Parent $target
            if (-not (Test-Path $targetDir)) {
                New-Item -ItemType Directory -Path $targetDir -Force | Out-Null
            }
        }

        if ($PSCmdlet.ShouldProcess($target, 'Submit MFA playbook ticket')) {
            if ($delivery -eq 'Webhook') {
                $headers = @{ 'Content-Type' = 'application/json' }
                $auth = if ($ticketConfig -and $ticketConfig.PSObject.Properties['Authorization']) { $ticketConfig.Authorization } else { $null }
                if ($auth) {
                    $authType = if ($auth.PSObject.Properties['Type']) { [string]$auth.Type } else { 'None' }
                    switch ($authType) {
                        'Bearer' {
                            if ($auth.PSObject.Properties['TokenEnvVar'] -and $auth.TokenEnvVar) {
                                $token = [Environment]::GetEnvironmentVariable($auth.TokenEnvVar, 'Process')
                                if (-not $token) {
                                    $token = [Environment]::GetEnvironmentVariable($auth.TokenEnvVar, 'Machine')
                                }
                                if ($token) {
                                    $headers['Authorization'] = "Bearer $token"
                                }
                                else {
                                    Write-Warning "Bearer token environment variable '$($auth.TokenEnvVar)' is not set. Falling back to file delivery."
                                    $delivery = 'File'
                                }
                            }
                        }
                        'Basic' {
                            $username = $null
                            $password = $null
                            if ($auth.PSObject.Properties['UsernameEnvVar'] -and $auth.UsernameEnvVar) {
                                $username = [Environment]::GetEnvironmentVariable($auth.UsernameEnvVar, 'Process')
                                if (-not $username) {
                                    $username = [Environment]::GetEnvironmentVariable($auth.UsernameEnvVar, 'Machine')
                                }
                            }
                            if ($auth.PSObject.Properties['PasswordEnvVar'] -and $auth.PasswordEnvVar) {
                                $password = [Environment]::GetEnvironmentVariable($auth.PasswordEnvVar, 'Process')
                                if (-not $password) {
                                    $password = [Environment]::GetEnvironmentVariable($auth.PasswordEnvVar, 'Machine')
                                }
                            }
                            if ($username -and $password) {
                                $token = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("{0}:{1}" -f $username, $password))
                                $headers['Authorization'] = "Basic $token"
                            }
                            else {
                                Write-Warning 'Basic authorization configured but username/password env vars are missing. Falling back to file delivery.'
                                $delivery = 'File'
                            }
                        }
                    }
                }

                if ($delivery -eq 'Webhook') {
                    $body = $payload | ConvertTo-Json -Depth 10
                    try {
                        $response = Invoke-RestMethod -Uri $endpoint -Method Post -Headers $headers -Body $body -ContentType 'application/json'
                    }
                    catch {
                        Write-Warning ("Ticket submission to '{0}' failed: {1}. Falling back to file delivery." -f $endpoint, $_.Exception.Message)
                        $delivery = 'File'
                        $fallbackDir = if ([System.IO.Path]::IsPathRooted($fallbackPath)) { $fallbackPath } else { Join-Path -Path $repoRoot -ChildPath $fallbackPath }
                        if (-not (Test-Path $fallbackDir)) {
                            New-Item -ItemType Directory -Path $fallbackDir -Force | Out-Null
                        }
                        $target = Join-Path -Path $fallbackDir -ChildPath ("ticket-{0}.json" -f ([guid]::NewGuid()))
                    }
                }
            }

            if ($delivery -eq 'File') {
                $targetDir = Split-Path -Parent $target
                if (-not (Test-Path $targetDir)) {
                    New-Item -ItemType Directory -Path $targetDir -Force | Out-Null
                }
                $payload | ConvertTo-Json -Depth 10 | Set-Content -Path $target -Encoding UTF8
            }
        }

        $result = [pscustomobject]@{
            TicketPayload = $payload
            Delivery      = $delivery
            Target        = $target
            Response      = $response
        }

        if ($PassThru) {
            $results += $result
        }
        else {
            $result
        }
    }

    end {
        if ($PassThru -and $results) {
            return $results
        }
    }
}

function New-MfaNotificationPayload {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [psobject] $Playbook,
        [string] $Provider = 'Generic'
    )

    process {
        if (-not $Playbook) { return }
        $playbookId = if ($Playbook.PSObject.Properties['PlaybookId']) { [string]$Playbook.PlaybookId } else { 'Playbook' }
        $user = if ($Playbook.PSObject.Properties['UserPrincipalName']) { [string]$Playbook.UserPrincipalName } else { 'Unknown user' }
        $severity = if ($Playbook.PSObject.Properties['Severity'] -and $Playbook.Severity) { [string]$Playbook.Severity } else { 'Medium' }

        $executedSteps = @()
        if ($Playbook.PSObject.Properties['ExecutedSteps']) {
            $executedSteps = @($Playbook.ExecutedSteps | Where-Object { $_ })
        }

        $summary = @(
            "*Playbook:* $playbookId",
            "*User:* $user",
            "*Severity:* $severity"
        )

        if ($Playbook.PSObject.Properties['DetectionId'] -and $Playbook.DetectionId) {
            $summary += "*Detection:* $($Playbook.DetectionId)"
        }

        if ($executedSteps) {
            $summary += '*Executed Steps:*'
            $summary += ($executedSteps | ForEach-Object { "- $_" })
        }

        $text = $summary -join "`n"

        switch ($Provider.ToLowerInvariant()) {
            'teams' { return @{ text = $text } }
            'slack' { return @{ text = $text } }
            default { return @{ message = $text } }
        }
    }
}

function Send-MfaPlaybookNotification {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [psobject] $Playbook,

        [string] $OutFile,
        [switch] $PassThru
    )

    begin {
        $notificationConfig = Get-MfaIntegrationConfig -Area 'Notifications'
        $repoRoot = Split-Path -Parent $PSScriptRoot
        $results = @()
    }

    process {
        if (-not $Playbook) { return }

        $provider = if ($notificationConfig -and $notificationConfig.PSObject.Properties['Provider']) { [string]$notificationConfig.Provider } else { 'Generic' }
        $payload = New-MfaNotificationPayload -Playbook $Playbook -Provider $provider
        if (-not $payload) { return }

        $webhookEnv = if ($notificationConfig -and $notificationConfig.PSObject.Properties['WebhookUrlEnvVar']) { [string]$notificationConfig.WebhookUrlEnvVar } else { $null }
        $webhookUrl = $null
        if ($webhookEnv) {
            $webhookUrl = [Environment]::GetEnvironmentVariable($webhookEnv, 'Process')
            if (-not $webhookUrl) {
                $webhookUrl = [Environment]::GetEnvironmentVariable($webhookEnv, 'Machine')
            }
        }

        $fallbackPath = 'notifications/outbox'
        if ($notificationConfig -and $notificationConfig.PSObject.Properties['FallbackPath'] -and $notificationConfig.FallbackPath) {
            $fallbackPath = [string]$notificationConfig.FallbackPath
        }

        $target = $OutFile
        $delivery = 'File'
        $response = $null

        if (-not $target) {
            if ($webhookUrl) {
                $target = $webhookUrl
                $delivery = 'Webhook'
            }
            else {
                $dir = if ([System.IO.Path]::IsPathRooted($fallbackPath)) { $fallbackPath } else { Join-Path -Path $repoRoot -ChildPath $fallbackPath }
                $target = Join-Path -Path $dir -ChildPath ("notification-{0}.json" -f ([guid]::NewGuid()))
            }
        }

        if ($delivery -eq 'File') {
            $targetDir = Split-Path -Parent $target
            if (-not (Test-Path $targetDir)) {
                New-Item -ItemType Directory -Path $targetDir -Force | Out-Null
            }
        }

        if ($PSCmdlet.ShouldProcess($target, 'Send MFA playbook notification')) {
            if ($delivery -eq 'Webhook') {
                $body = $payload | ConvertTo-Json -Depth 10
                try {
                    $response = Invoke-RestMethod -Uri $webhookUrl -Method Post -Body $body -ContentType 'application/json'
                }
                catch {
                    Write-Warning ("Notification delivery to '{0}' failed: {1}. Falling back to file delivery." -f $webhookUrl, $_.Exception.Message)
                    $delivery = 'File'
                    $dir = if ([System.IO.Path]::IsPathRooted($fallbackPath)) { $fallbackPath } else { Join-Path -Path $repoRoot -ChildPath $fallbackPath }
                    if (-not (Test-Path $dir)) {
                        New-Item -ItemType Directory -Path $dir -Force | Out-Null
                    }
                    $target = Join-Path -Path $dir -ChildPath ("notification-{0}.json" -f ([guid]::NewGuid()))
                }
            }

            if ($delivery -eq 'File') {
                $targetDir = Split-Path -Parent $target
                if (-not (Test-Path $targetDir)) {
                    New-Item -ItemType Directory -Path $targetDir -Force | Out-Null
                }
                $payload | ConvertTo-Json -Depth 10 | Set-Content -Path $target -Encoding UTF8
            }
        }

        $result = [pscustomobject]@{
            NotificationPayload = $payload
            Delivery            = $delivery
            Target              = $target
            Response            = $response
        }

        if ($PassThru) {
            $results += $result
        }
        else {
            $result
        }
    }

    end {
        if ($PassThru -and $results) {
            return $results
        }
    }
}

function Invoke-MfaPlaybookOutputs {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [psobject] $Playbook,

        [string] $TicketOutFile,
        [string] $NotificationOutFile,
        [switch] $SkipTicket,
        [switch] $SkipNotification,
        [switch] $PassThru
    )

    begin {
        $results = @()
        Write-Verbose 'Invoking playbook output helpers.'
    }

    process {
        if (-not $Playbook) { return }

        $targetUser = if ($Playbook.PSObject.Properties['UserPrincipalName']) { $Playbook.UserPrincipalName } else { 'unknown user' }
        Write-Verbose ("Processing playbook '{0}' for {1}." -f $Playbook.PlaybookId, $targetUser)

        $ticketResult = $null
        if (-not $SkipTicket) {
            Write-Progress -Activity 'Submitting playbook ticket' -Status 'Generating payload' -PercentComplete 10
            $ticketParams = @{
                Playbook = $Playbook
            }
            if ($TicketOutFile) {
                $ticketParams['OutFile'] = $TicketOutFile
            }
            $ticketResult = Submit-MfaPlaybookTicket @ticketParams
            Write-Progress -Activity 'Submitting playbook ticket' -Completed
            if ($ticketResult) {
                Write-Verbose ("Ticket target: {0}" -f $ticketResult.Target)
            }
        }

        $notificationResult = $null
        if (-not $SkipNotification) {
            Write-Progress -Activity 'Sending playbook notification' -Status 'Generating payload' -PercentComplete 10
            $notificationParams = @{
                Playbook = $Playbook
            }
            if ($NotificationOutFile) {
                $notificationParams['OutFile'] = $NotificationOutFile
            }
            $notificationResult = Send-MfaPlaybookNotification @notificationParams
            Write-Progress -Activity 'Sending playbook notification' -Completed
            if ($notificationResult) {
                Write-Verbose ("Notification target: {0}" -f $notificationResult.Target)
            }
        }

        $summary = [pscustomobject]@{
            Playbook           = $Playbook
            TicketResult       = $ticketResult
            NotificationResult = $notificationResult
        }

        if ($PassThru) {
            $results += $summary
        }
        else {
            $summary
        }
    }

    end {
        if ($PassThru -and $results) {
            Write-Verbose ("Aggregated playbook outputs: {0}" -f $results.Count)
            return $results
        }
    }
}

function New-MfaHtmlReport {
    [CmdletBinding()]
    param(
        [psobject[]] $Detections,
        [psobject[]] $Playbooks,
        [psobject[]] $BestPractices,
        [string] $Path,
        [switch] $OpenInBrowser
    )

    Write-Verbose 'Starting HTML report composition.'
    $encode = {
        param($value)
        if ($null -eq $value) { return '' }
        return [System.Net.WebUtility]::HtmlEncode([string]$value)
    }

    $detCollection = @()
    if ($Detections) {
        $detCollection = @($Detections | Where-Object { $_ })
    }

    $playCollection = @()
    foreach ($item in @($Playbooks)) {
        if (-not $item) { continue }

        $playbook = $null
        $ticket = $null
        $notification = $null

        if ($item.PSObject.Properties['Playbook'] -and $item.Playbook) {
            $playbook = $item.Playbook
            if ($item.PSObject.Properties['TicketResult']) { $ticket = $item.TicketResult }
            if ($item.PSObject.Properties['NotificationResult']) { $notification = $item.NotificationResult }
        }
        else {
            $playbook = $item
            if ($item.PSObject.Properties['TicketResult']) { $ticket = $item.TicketResult }
            if ($item.PSObject.Properties['NotificationResult']) { $notification = $item.NotificationResult }
        }

        if ($playbook) {
            $ticketTarget = $null
            if ($ticket -and $ticket.PSObject.Properties['Target']) {
                $ticketTarget = $ticket.Target
            }
            elseif ($item.PSObject.Properties['TicketTarget']) {
                $ticketTarget = $item.TicketTarget
            }

            $notificationTarget = $null
            if ($notification -and $notification.PSObject.Properties['Target']) {
                $notificationTarget = $notification.Target
            }
            elseif ($item.PSObject.Properties['NotificationTarget']) {
                $notificationTarget = $item.NotificationTarget
            }

            $playCollection += [pscustomobject]@{
                Playbook           = $playbook
                TicketTarget       = $ticketTarget
                NotificationTarget = $notificationTarget
            }
        }
    }

    $playbookFriendlyNames = @{
        'MFA-PL-001' = 'Reset Dormant Method'
        'MFA-PL-002' = 'Contain High-Risk Sign-in'
        'MFA-PL-003' = 'Enforce Privileged Role MFA'
        'MFA-PL-004' = 'Triage Suspicious Score'
        'MFA-PL-005' = 'Contain Repeated MFA Failures'
        'MFA-PL-006' = 'Investigate Impossible Travel'
    }

    $defaultPlaybookRecommendations = @{
        'MFA-DET-001' = @('MFA-PL-001')
        'MFA-DET-002' = @('MFA-PL-002')
        'MFA-DET-003' = @('MFA-PL-003')
        'MFA-DET-004' = @('MFA-PL-005')
        'MFA-DET-005' = @('MFA-PL-006')
        'MFA-SCORE'   = @('MFA-PL-004')
    }

    $playbookLookup = @{}
    foreach ($entry in $playCollection) {
        $playbook = $entry.Playbook
        if (-not $playbook) { continue }

        $candidateKeys = @()
        foreach ($propName in @('DetectionId','SignalId')) {
            if ($playbook.PSObject.Properties[$propName] -and $playbook.$propName) {
                $candidateKeys += [string]$playbook.$propName
            }
        }
        $candidateKeys = @($candidateKeys | Where-Object { $_ }) | Sort-Object -Unique

        foreach ($key in $candidateKeys) {
            if (-not $playbookLookup.ContainsKey($key)) {
                $playbookLookup[$key] = @()
            }
            $playbookLookup[$key] += $playbook
        }
    }

    $bpCollection = @()
    if ($BestPractices) {
        $bpCollection = @($BestPractices | Where-Object { $_ })
    }

    $formatList = {
        param([System.Collections.IEnumerable] $Items)

        $values = @()
        foreach ($item in $Items) {
            if ($null -ne $item -and $item -ne '') {
                $values += [string]$item
            }
        }

        if ($values.Count -eq 0) {
            return ''
        }

        $unique = $values | Sort-Object -Unique
        if ($unique.Count -le 3) {
            return $unique -join ', '
        }

        return (($unique[0..2] -join ', ') + ', …')
    }

    $fatigueNoteExists = $bpCollection | Where-Object {
        $_.PSObject.Properties['Title'] -and $_.Title -eq 'Enforce number matching for Microsoft Authenticator push'
    }
    if (-not $fatigueNoteExists) {
        $fatigueUsers = @()
        $fatigueDetections = @($detCollection | Where-Object {
            $_.PSObject.Properties['DetectionId'] -and $_.DetectionId -eq 'MFA-DET-004'
        })
        if ($fatigueDetections) {
            $fatigueUsers += ($fatigueDetections | ForEach-Object { $_.UserPrincipalName })
        }

        $fatigueScores = @($detCollection | Where-Object {
            $_.PSObject.Properties['Indicators'] -and
            ((@($_.Indicators) | ForEach-Object { $_.Type }) -contains 'RepeatedFailures')
        })
        if ($fatigueScores) {
            $fatigueUsers += ($fatigueScores | ForEach-Object { $_.UserPrincipalName })
        }

        $fatigueUsers = @($fatigueUsers | Where-Object { $_ }) | Sort-Object -Unique
        if ($fatigueUsers.Count -gt 0) {
            $evidenceStrings = @(
                $fatigueDetections | ForEach-Object {
                    if ($_.PSObject.Properties['FailureReasons'] -and $_.FailureReasons) {
                        $_.FailureReasons
                    }
                }
            ) | Where-Object { $_ }

            $evidenceText = $null
            if ($evidenceStrings) {
                $flatEvidence = (($evidenceStrings -join ';') -split ';') | ForEach-Object { $_.Trim() } | Where-Object { $_ }
                if ($flatEvidence) {
                    $evidenceText = "Observed failure reasons: {0}" -f (($flatEvidence | Sort-Object -Unique) -join '; ')
                }
            }

            $userSummary = & $formatList $fatigueUsers
            $summaryText = if ($userSummary) {
                "Repeated MFA denials detected for $userSummary. Enforce Microsoft Authenticator number matching through Conditional Access authentication strength and retire simple approve/deny prompts."
            }
            else {
                "Repeated MFA push denials detected. Enforce Microsoft Authenticator number matching through Conditional Access authentication strength and retire simple approve/deny prompts."
            }

            $bpCollection += [pscustomobject]@{
                Title      = 'Enforce number matching for Microsoft Authenticator push'
                Importance = 'High'
                Audience   = 'Conditional Access owners / IAM'
                Summary    = $summaryText
                Evidence   = $evidenceText
            }
        }
    }

    $severityOrder = @('Critical', 'High', 'Medium', 'Low', 'Informational')
    $severityClass = {
        param([string] $value)
        switch ($value.ToLowerInvariant()) {
            'critical' { 'sev-critical' }
            'high'     { 'sev-high' }
            'medium'   { 'sev-medium' }
            'low'      { 'sev-low' }
            default    { 'sev-default' }
        }
    }

    $detSeverityCounts = [ordered]@{}
    foreach ($sev in $severityOrder) { $detSeverityCounts[$sev] = 0 }
    foreach ($det in $detCollection) {
        $sev = if ($det.PSObject.Properties['Severity'] -and $det.Severity) { [string]$det.Severity } else { 'Informational' }
        if (-not $detSeverityCounts.Contains($sev)) { $detSeverityCounts[$sev] = 0 }
        $detSeverityCounts[$sev]++
    }

    $playSeverityCounts = [ordered]@{}
    foreach ($sev in $severityOrder) { $playSeverityCounts[$sev] = 0 }
    foreach ($entry in $playCollection) {
        $play = $entry.Playbook
        $sev = if ($play -and $play.PSObject.Properties['Severity'] -and $play.Severity) { [string]$play.Severity } else { 'Informational' }
        if (-not $playSeverityCounts.Contains($sev)) { $playSeverityCounts[$sev] = 0 }
        $playSeverityCounts[$sev]++
    }

    $totalDetections = $detCollection.Count
    $totalPlaybooks = $playCollection.Count
    Write-Verbose ("Detections included: {0}; Playbooks included: {1}" -f $totalDetections, $totalPlaybooks)
    $detScale = if ($totalDetections -gt 0) { [double]$totalDetections } else { 1 }
    $playScale = if ($totalPlaybooks -gt 0) { [double]$totalPlaybooks } else { 1 }

    Write-Progress -Activity 'Generating MFA HTML report' -Status 'Composing content' -PercentComplete 25
    $sb = [System.Text.StringBuilder]::new()
    $null = $sb.AppendLine('<!DOCTYPE html>')
    $null = $sb.AppendLine('<html lang="en">')
    $null = $sb.AppendLine('<head>')
    $null = $sb.AppendLine('<meta charset="utf-8" />')
    $null = $sb.AppendLine('<title>MFA Check &amp; Steer Summary</title>')
    $null = $sb.AppendLine('<style>')
    $null = $sb.AppendLine('body { font-family: Segoe UI, Arial, sans-serif; margin: 24px; color: #1f2933; background: #f4f7fb; }')
    $null = $sb.AppendLine('h1 { margin-bottom: 0.2em; }')
    $null = $sb.AppendLine('h2 { margin-top: 1.6em; }')
    $null = $sb.AppendLine('table { border-collapse: collapse; width: 100%; margin-top: 0.6em; }')
    $null = $sb.AppendLine('th, td { border: 1px solid #d2d6dc; padding: 8px 10px; text-align: left; }')
    $null = $sb.AppendLine('th { background-color: #e4ebf2; }')
    $null = $sb.AppendLine('.sev-critical { background-color: #fee2e2; }')
    $null = $sb.AppendLine('.sev-high { background-color: #fef3c7; }')
    $null = $sb.AppendLine('.sev-medium { background-color: #e0f2fe; }')
    $null = $sb.AppendLine('.sev-low { background-color: #ecfdf5; }')
    $null = $sb.AppendLine('.sev-default { background-color: #e5e7eb; }')
    $null = $sb.AppendLine('.meta { color: #52606d; font-size: 0.9em; margin-bottom: 1.4em; }')
    $null = $sb.AppendLine('.summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin: 20px 0; }')
    $null = $sb.AppendLine('.summary-card { background: linear-gradient(135deg, #2563eb, #1e3a8a); color: #fff; padding: 18px; border-radius: 12px; box-shadow: 0 12px 24px rgba(37, 99, 235, 0.22); }')
    $null = $sb.AppendLine('.summary-card.secondary { background: linear-gradient(135deg, #059669, #047857); box-shadow: 0 12px 24px rgba(5, 150, 105, 0.22); }')
    $null = $sb.AppendLine('.summary-card h3 { margin: 0; font-weight: 600; font-size: 1rem; }')
    $null = $sb.AppendLine('.summary-card .value { font-size: 2.6rem; margin-top: 8px; font-weight: 700; }')
    $null = $sb.AppendLine('.summary-card .subtext { font-size: 0.85rem; opacity: 0.85; margin-top: 6px; }')
    $null = $sb.AppendLine('.severity-board { background: #fff; border-radius: 12px; padding: 18px; box-shadow: 0 12px 22px rgba(15, 23, 42, 0.08); margin-top: 20px; }')
    $null = $sb.AppendLine('.severity-board h3 { margin: 0 0 12px 0; font-size: 1.1rem; }')
    $null = $sb.AppendLine('.meter { margin-bottom: 10px; }')
    $null = $sb.AppendLine('.meter-label { display: flex; justify-content: space-between; font-size: 0.85rem; margin-bottom: 4px; }')
    $null = $sb.AppendLine('.meter-bar { height: 10px; border-radius: 6px; overflow: hidden; background: #e5e7eb; }')
    $null = $sb.AppendLine('.meter-fill { height: 10px; border-radius: 6px; transition: width 0.4s ease; }')
    $null = $sb.AppendLine('.cards { margin-top: 20px; display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 16px; }')
    $null = $sb.AppendLine('.card { background: #fff; border-radius: 12px; padding: 18px; box-shadow: 0 12px 24px rgba(15, 23, 42, 0.08); display: flex; flex-direction: column; gap: 10px; }')
    $null = $sb.AppendLine('.card .title { font-size: 1.05rem; font-weight: 600; display: flex; justify-content: space-between; align-items: center; }')
    $null = $sb.AppendLine('.card.best-card { border-left: 4px solid #2563eb; }')
    $null = $sb.AppendLine('.chip { padding: 2px 10px; border-radius: 999px; font-size: 0.75rem; font-weight: 600; color: #fff; }')
    $null = $sb.AppendLine('.info { font-size: 0.9rem; color: #4b5563; }')
    $null = $sb.AppendLine('.target { font-size: 0.85rem; color: #2563eb; word-break: break-word; }')
    $null = $sb.AppendLine('</style>')
    $null = $sb.AppendLine('</head>')
    $null = $sb.AppendLine('<body>')
    $null = $sb.AppendLine('<h1>MFA Check &amp; Steer Summary</h1>')
    $null = $sb.AppendLine(("<div class=""meta"">Generated UTC: {0}</div>" -f (& $encode (Get-Date).ToUniversalTime().ToString('u'))))

    $null = $sb.AppendLine('<div class="summary-grid">')
    $null = $sb.AppendLine(('<div class="summary-card"><h3>Total Detections</h3><div class="value">{0}</div><div class="subtext">Signals requiring investigation</div></div>' -f $totalDetections))
    $null = $sb.AppendLine(('<div class="summary-card secondary"><h3>Playbooks Triggered</h3><div class="value">{0}</div><div class="subtext">Automated responses executed</div></div>' -f $totalPlaybooks))
    $null = $sb.AppendLine('</div>')

    $null = $sb.AppendLine('<div class="severity-board">')
    $null = $sb.AppendLine('<h3>Detection Severity Mix</h3>')
    foreach ($sev in $severityOrder) {
        if (-not $detSeverityCounts.Contains($sev)) { continue }
        $count = $detSeverityCounts[$sev]
        $percent = [math]::Round(($count / $detScale) * 100, 1)
        $null = $sb.AppendLine('<div class="meter">')
        $null = $sb.AppendLine(('<div class="meter-label"><span>{0}</span><span>{1} ({2}%)</span></div>' -f (& $encode $sev), $count, $percent))
        $null = $sb.AppendLine('<div class="meter-bar">')
        $null = $sb.AppendLine(('<div class="meter-fill {0}" style="width: {1}%;"></div>' -f (& $severityClass $sev), [math]::Max($percent, 0)))
        $null = $sb.AppendLine('</div></div>')
    }
    $null = $sb.AppendLine('<h3>Playbook Severity Mix</h3>')
    foreach ($sev in $severityOrder) {
        if (-not $playSeverityCounts.Contains($sev)) { continue }
        $count = $playSeverityCounts[$sev]
        $percent = [math]::Round(($count / $playScale) * 100, 1)
        $null = $sb.AppendLine('<div class="meter">')
        $null = $sb.AppendLine(('<div class="meter-label"><span>{0}</span><span>{1} ({2}%)</span></div>' -f (& $encode $sev), $count, $percent))
        $null = $sb.AppendLine('<div class="meter-bar">')
        $null = $sb.AppendLine(('<div class="meter-fill {0}" style="width: {1}%;"></div>' -f (& $severityClass $sev), [math]::Max($percent, 0)))
        $null = $sb.AppendLine('</div></div>')
    }
    $null = $sb.AppendLine('</div>')

    if ($bpCollection.Count -gt 0) {
        $null = $sb.AppendLine("<h2>Best Practice Highlights ({0})</h2>" -f $bpCollection.Count)
        $null = $sb.AppendLine('<div class="cards">')
        foreach ($note in $bpCollection) {
            if (-not $note) { continue }
            $importance = if ($note.PSObject.Properties['Importance'] -and $note.Importance) { [string]$note.Importance } else { 'Informational' }
            $class = & $severityClass $importance
            $title = if ($note.PSObject.Properties['Title'] -and $note.Title) { [string]$note.Title } else { 'Best practice' }
            $audience = if ($note.PSObject.Properties['Audience'] -and $note.Audience) { [string]$note.Audience } else { $null }
            $summary = if ($note.PSObject.Properties['Summary'] -and $note.Summary) { [string]$note.Summary } else { $null }

            $evidenceString = $null
            if ($note.PSObject.Properties['Evidence']) {
                $rawEvidence = $note.Evidence
                if ($null -ne $rawEvidence) {
                    if ($rawEvidence -is [System.Collections.IEnumerable] -and -not ($rawEvidence -is [string])) {
                        $evidenceItems = @($rawEvidence | Where-Object { $_ }) | ForEach-Object { [string]$_ }
                        if ($evidenceItems.Count -gt 0) {
                            $evidenceString = $evidenceItems -join '; '
                        }
                    }
                    else {
                        $text = [string]$rawEvidence
                        if ($text) {
                            $evidenceString = $text
                        }
                    }
                }
            }

            $actionItems = @()
            if ($note.PSObject.Properties['Actions']) {
                $rawActions = $note.Actions
                if ($rawActions -is [System.Collections.IEnumerable] -and -not ($rawActions -is [string])) {
                    $actionItems = @($rawActions | Where-Object { $_ }) | ForEach-Object { [string]$_ }
                }
                elseif ($rawActions) {
                    $actionItems = @([string]$rawActions)
                }
            }

            $null = $sb.AppendLine('<div class="card best-card">')
            $null = $sb.AppendLine(('<div class="title"><span>{0}</span><span class="chip {1}">{2}</span></div>' -f (& $encode $title), $class, (& $encode $importance)))
            if ($audience) {
                $null = $sb.AppendLine(('<div class="info"><strong>Audience:</strong> {0}</div>' -f (& $encode $audience)))
            }
            if ($summary) {
                $null = $sb.AppendLine(('<div class="info">{0}</div>' -f (& $encode $summary)))
            }
            if ($evidenceString) {
                $null = $sb.AppendLine(('<div class="info"><strong>Evidence:</strong> {0}</div>' -f (& $encode $evidenceString)))
            }
            foreach ($action in $actionItems) {
                $null = $sb.AppendLine(('<div class="info"><strong>Action:</strong> {0}</div>' -f (& $encode $action)))
            }
            $null = $sb.AppendLine('</div>')
        }
        $null = $sb.AppendLine('</div>')
    }

    $null = $sb.AppendLine("<h2>Detections ({0})</h2>" -f $detCollection.Count)
    if ($detCollection.Count -gt 0) {
        $null = $sb.AppendLine('<table>')
        $null = $sb.AppendLine('<thead><tr><th>Detection ID</th><th>User</th><th>Severity</th><th>Control Owner</th><th>Response SLA (hrs)</th><th>Details</th></tr></thead>')
        $null = $sb.AppendLine('<tbody>')
        $detectionDetails = {
            param($det)

            if ($det.PSObject.Properties['Summary'] -and $det.Summary) {
                return [string]$det.Summary
            }

            if ($det.PSObject.Properties['Score'] -and $det.Score) {
                $scoreText = "Suspicious activity score: {0}" -f $det.Score
                $indicatorNames = @()
                if ($det.PSObject.Properties['Indicators'] -and $det.Indicators) {
                    foreach ($indicator in @($det.Indicators)) {
                        if (-not $indicator) { continue }
                        if ($indicator.PSObject.Properties['Type'] -and $indicator.Type) {
                            $indicatorNames += [string]$indicator.Type
                        }
                        elseif ($indicator -is [string]) {
                            $indicatorNames += [string]$indicator
                        }
                    }
                }

                $indicatorNames = @($indicatorNames | Where-Object { $_ }) | Sort-Object -Unique
                if ($indicatorNames.Count -gt 0) {
                    return ("{0}. Signals: {1}" -f $scoreText, ($indicatorNames -join ', '))
                }

                return $scoreText
            }

            if ($det.PSObject.Properties['FailureReasons'] -and $det.FailureReasons) {
                $reasons = @($det.FailureReasons)
                if ($reasons.Count -gt 0) {
                    $flat = (($reasons -join ';') -split ';') | ForEach-Object { $_.Trim() } | Where-Object { $_ }
                    if ($flat) {
                        return ("Failure reasons: {0}" -f ((@($flat | Sort-Object -Unique)) -join ', '))
                    }
                }
            }

            if ($det.PSObject.Properties['MethodType'] -and $det.MethodType) {
                if ($det.PSObject.Properties['LastUpdatedDateTime'] -and $det.LastUpdatedDateTime) {
                    $parsed = ConvertTo-MfaDateTime -Value $det.LastUpdatedDateTime
                    if ($parsed) {
                        return ("Method {0} last updated {1:u}" -f $det.MethodType, $parsed)
                    }
                }
                return ("Method {0} flagged for review" -f $det.MethodType)
            }

            if ($det.PSObject.Properties['RiskDetail'] -and $det.RiskDetail) {
                return ("Risk detail: {0}" -f $det.RiskDetail)
            }

            if ($det.PSObject.Properties['CorrelationId'] -and $det.CorrelationId) {
                return ("Correlation ID: {0}" -f $det.CorrelationId)
            }
            return ''
        }
        $playbookSummary = {
            param([string[]] $PlaybookIds)

            if (-not $PlaybookIds -or $PlaybookIds.Count -eq 0) {
                return $null
            }

            $unique = @($PlaybookIds | Where-Object { $_ }) | Sort-Object -Unique
            if ($unique.Count -eq 0) {
                return $null
            }

            $names = foreach ($id in $unique) {
                if ($playbookFriendlyNames.ContainsKey($id)) {
                    "{0} – {1}" -f $id, $playbookFriendlyNames[$id]
                }
                else {
                    $id
                }
            }

            $suffix = if ($names.Count -gt 1) { 's' } else { '' }
            return ("Recommended playbook{0}: {1}" -f $suffix, ($names -join ', '))
        }

        foreach ($det in $detCollection) {
            $severity = if ($det.PSObject.Properties['Severity']) { [string]$det.Severity } else { '' }
            $class = switch ($severity.ToLowerInvariant()) {
                'critical' { 'sev-critical' }
                'high' { 'sev-high' }
                'medium' { 'sev-medium' }
                default { 'sev-low' }
            }
            $detectionId = ''
            if ($det.PSObject.Properties['DetectionId'] -and $det.DetectionId) {
                $detectionId = [string]$det.DetectionId
            }
            elseif ($det.PSObject.Properties['SignalId'] -and $det.SignalId) {
                $detectionId = [string]$det.SignalId
            }
            elseif ($det.PSObject.Properties['Source'] -and $det.Source) {
                $detectionId = [string]$det.Source
            }
            elseif ($det.PSObject.Properties['RecordType'] -and $det.RecordType) {
                $detectionId = [string]$det.RecordType
            }

            $user = if ($det.PSObject.Properties['UserPrincipalName']) { [string]$det.UserPrincipalName } else { '' }
            $controlOwner = if ($det.PSObject.Properties['ControlOwner']) { [string]$det.ControlOwner } else { '' }
            $sla = if ($det.PSObject.Properties['ResponseSlaHours']) { [string]$det.ResponseSlaHours } else { '' }
            $detailText = & $detectionDetails $det
            if (-not $detailText) {
                $detailText = 'Additional context not supplied.'
            }
            $detKeys = @()
            if ($det.PSObject.Properties['DetectionId'] -and $det.DetectionId) { $detKeys += [string]$det.DetectionId }
            if ($det.PSObject.Properties['SignalId'] -and $det.SignalId) { $detKeys += [string]$det.SignalId }
            if ($detectionId) { $detKeys += [string]$detectionId }
            $detKeys = @($detKeys | Where-Object { $_ }) | Sort-Object -Unique

            $playbookIds = @()
            foreach ($key in $detKeys) {
                if ($playbookLookup.ContainsKey($key)) {
                    foreach ($play in $playbookLookup[$key]) {
                        if ($play -and $play.PSObject.Properties['PlaybookId'] -and $play.PlaybookId) {
                            $playbookIds += [string]$play.PlaybookId
                        }
                    }
                }
            }
            if ($playbookIds.Count -eq 0) {
                foreach ($key in $detKeys) {
                    if ($defaultPlaybookRecommendations.ContainsKey($key)) {
                        $playbookIds += $defaultPlaybookRecommendations[$key]
                    }
                }
            }
            $playbookIds = @($playbookIds | Where-Object { $_ }) | Sort-Object -Unique
            $remediationText = $null
            if ($playbookIds.Count -gt 0) {
                $remediationText = & $playbookSummary $playbookIds
            }

            if ($remediationText) {
                if ($detailText -and ($detailText.Trim().EndsWith('.') -eq $false)) {
                    $detailText = $detailText.Trim() + '.'
                }
                $detailText = ($detailText.Trim() + ' ' + $remediationText).Trim()
            }

            $null = $sb.AppendLine(("<tr class=""{0}""><td>{1}</td><td>{2}</td><td>{3}</td><td>{4}</td><td>{5}</td><td>{6}</td></tr>" -f
                $class,
                (& $encode $detectionId),
                (& $encode $user),
                (& $encode $severity),
                (& $encode $controlOwner),
                (& $encode $sla),
                (& $encode $detailText)
            ))
        }
        $null = $sb.AppendLine('</tbody></table>')
        $null = $sb.AppendLine('<div class="cards">')
        foreach ($det in $detCollection) {
            $severity = if ($det.PSObject.Properties['Severity']) { [string]$det.Severity } else { 'Informational' }
            $class = & $severityClass $severity
            $detectionId = if ($det.PSObject.Properties['DetectionId']) { [string]$det.DetectionId } else { 'Unknown Detection' }
            $user = if ($det.PSObject.Properties['UserPrincipalName']) { [string]$det.UserPrincipalName } else { 'Unknown user' }
            $controlOwner = if ($det.PSObject.Properties['ControlOwner']) { [string]$det.ControlOwner } else { 'Unassigned' }
            $sla = if ($det.PSObject.Properties['ResponseSlaHours']) { [string]$det.ResponseSlaHours } else { '—' }

            $null = $sb.AppendLine('<div class="card">')
            $null = $sb.AppendLine(('<div class="title"><span>{0}</span><span class="chip {1}">{2}</span></div>' -f (& $encode $detectionId), $class, (& $encode $severity)))
            $null = $sb.AppendLine(('<div class="info"><strong>User:</strong> {0}</div>' -f (& $encode $user)))
            $null = $sb.AppendLine(('<div class="info"><strong>Control owner:</strong> {0}</div>' -f (& $encode $controlOwner)))
            $null = $sb.AppendLine(('<div class="info"><strong>Response SLA:</strong> {0} hour(s)</div>' -f (& $encode $sla)))
            $null = $sb.AppendLine('</div>')
        }
        $null = $sb.AppendLine('</div>')
    }
    else {
        $null = $sb.AppendLine('<p>No detections recorded for this period.</p>')
    }

    $null = $sb.AppendLine("<h2>Playbook Actions ({0})</h2>" -f $playCollection.Count)
    if ($playCollection.Count -gt 0) {
        $null = $sb.AppendLine('<table>')
        $null = $sb.AppendLine('<thead><tr><th>Playbook</th><th>User</th><th>Severity</th><th>Ticket Target</th><th>Notification Target</th></tr></thead>')
        $null = $sb.AppendLine('<tbody>')
        foreach ($entry in $playCollection) {
            $playbook = $entry.Playbook
            $severity = if ($playbook -and $playbook.PSObject.Properties['Severity']) { [string]$playbook.Severity } else { '' }
            $class = switch ($severity.ToLowerInvariant()) {
                'critical' { 'sev-critical' }
                'high' { 'sev-high' }
                'medium' { 'sev-medium' }
                default { 'sev-low' }
            }

            $ticketTarget = if ($entry.TicketTarget) { $entry.TicketTarget } else { 'Not sent' }
            $notificationTarget = if ($entry.NotificationTarget) { $entry.NotificationTarget } else { 'Not sent' }
            $playbookId = if ($playbook -and $playbook.PSObject.Properties['PlaybookId']) { [string]$playbook.PlaybookId } else { '' }
            $user = if ($playbook -and $playbook.PSObject.Properties['UserPrincipalName']) { [string]$playbook.UserPrincipalName } else { '' }

            $null = $sb.AppendLine(("<tr class=""{0}""><td>{1}</td><td>{2}</td><td>{3}</td><td>{4}</td><td>{5}</td></tr>" -f
                $class,
                (& $encode $playbookId),
                (& $encode $user),
                (& $encode $severity),
                (& $encode $ticketTarget),
                (& $encode $notificationTarget)
            ))
        }
        $null = $sb.AppendLine('</tbody></table>')
        $null = $sb.AppendLine('<div class="cards">')
        foreach ($entry in $playCollection) {
            $playbook = $entry.Playbook
            $severity = if ($playbook -and $playbook.PSObject.Properties['Severity']) { [string]$playbook.Severity } else { 'Informational' }
            $class = & $severityClass $severity
            $playbookId = if ($playbook -and $playbook.PSObject.Properties['PlaybookId']) { [string]$playbook.PlaybookId } else { 'Playbook' }
            $user = if ($playbook -and $playbook.PSObject.Properties['UserPrincipalName']) { [string]$playbook.UserPrincipalName } else { 'Unknown user' }
            $ticketTarget = if ($entry.TicketTarget) { [string]$entry.TicketTarget } else { 'Not sent' }
            $notificationTarget = if ($entry.NotificationTarget) { [string]$entry.NotificationTarget } else { 'Not sent' }

            $null = $sb.AppendLine('<div class="card">')
            $null = $sb.AppendLine(('<div class="title"><span>{0}</span><span class="chip {1}">{2}</span></div>' -f (& $encode $playbookId), $class, (& $encode $severity)))
            $null = $sb.AppendLine(('<div class="info"><strong>User:</strong> {0}</div>' -f (& $encode $user)))
            $null = $sb.AppendLine(('<div class="info"><strong>Ticket:</strong></div><div class="target">{0}</div>' -f (& $encode $ticketTarget)))
            $null = $sb.AppendLine(('<div class="info"><strong>Notification:</strong></div><div class="target">{0}</div>' -f (& $encode $notificationTarget)))
            $null = $sb.AppendLine('</div>')
        }
        $null = $sb.AppendLine('</div>')
    }
    else {
        $null = $sb.AppendLine('<p>No playbook actions recorded for this period.</p>')
    }

    $null = $sb.AppendLine('</body></html>')

    $html = $sb.ToString()
    $writtenPath = $null
    if ($Path) {
        $directory = Split-Path -Parent $Path
        if ($directory -and -not (Test-Path $directory)) {
            New-Item -ItemType Directory -Path $directory -Force | Out-Null
        }
        Write-Progress -Activity 'Generating MFA HTML report' -Status 'Writing output' -PercentComplete 80
        $html | Set-Content -Path $Path -Encoding UTF8
        try {
            $writtenPath = (Resolve-Path -Path $Path).ProviderPath
        }
        catch {
            $writtenPath = $Path
        }

        if ($OpenInBrowser) {
            Write-Verbose ("Opening HTML report in default browser: {0}" -f $writtenPath)
            try {
                Start-Process -FilePath $writtenPath -ErrorAction Stop
            }
            catch {
                Write-Warning ("Failed to open HTML report in browser: {0}" -f $_.Exception.Message)
            }
        }
    }
    Write-Progress -Activity 'Generating MFA HTML report' -Completed

    return [pscustomobject]@{
        Html            = $html
        Path            = $writtenPath
        DetectionCount  = $detCollection.Count
        PlaybookCount   = $playCollection.Count
        BestPracticeCount = $bpCollection.Count
        BestPractices   = @($bpCollection)
    }
}

Export-ModuleMember -Function Get-MfaEnvironmentStatus, Test-MfaGraphPrerequisite, Get-MfaEntraSignIn, Get-MfaEntraRegistration, Connect-MfaGraphDeviceCode, ConvertTo-MfaCanonicalSignIn, ConvertTo-MfaCanonicalRegistration, Invoke-MfaDetectionDormantMethod, Invoke-MfaDetectionHighRiskSignin, Invoke-MfaDetectionRepeatedMfaFailure, Invoke-MfaDetectionImpossibleTravelSuccess, Invoke-MfaDetectionPrivilegedRoleNoMfa, Invoke-MfaSuspiciousActivityScore, Get-MfaDetectionConfiguration, Get-MfaIntegrationConfig, Test-MfaPlaybookAuthorization, Invoke-MfaPlaybookResetDormantMethod, Invoke-MfaPlaybookEnforcePrivilegedRoleMfa, Invoke-MfaPlaybookContainHighRiskSignin, Invoke-MfaPlaybookContainRepeatedFailure, Invoke-MfaPlaybookInvestigateImpossibleTravel, Invoke-MfaPlaybookTriageSuspiciousScore, New-MfaTicketPayload, Submit-MfaPlaybookTicket, New-MfaNotificationPayload, Send-MfaPlaybookNotification, Invoke-MfaPlaybookOutputs, New-MfaHtmlReport, Invoke-MfaScenarioReport, Invoke-MfaTenantReport

function Invoke-MfaScenarioReport {
    [CmdletBinding(DefaultParameterSetName = 'Path')]
    param(
        [Parameter(Mandatory, ParameterSetName = 'Path')]
        [string] $ScenarioPath,

        [Parameter(Mandatory, ParameterSetName = 'Object')]
        [psobject] $Scenario,

        [string] $OutputDirectory,
        [switch] $SkipAuthorization,
        [switch] $OpenReport,
        [switch] $PassThru
    )

    $rawScenario = $null
    $scenarioSource = $null

    if ($PSCmdlet.ParameterSetName -eq 'Path') {
        if (-not (Test-Path -Path $ScenarioPath)) {
            throw "Scenario file '$ScenarioPath' was not found."
        }

        Write-Verbose ("Loading scenario from '{0}'." -f $ScenarioPath)
        $rawScenario = Get-Content -Path $ScenarioPath -Raw | ConvertFrom-Json
        try {
            $scenarioSource = (Resolve-Path -Path $ScenarioPath).ProviderPath
        }
        catch {
            $scenarioSource = $ScenarioPath
        }
    }
    else {
        if (-not $Scenario) {
            throw "Scenario object input is empty. Provide a populated object via -Scenario."
        }
        $rawScenario = $Scenario
    }

    $signIns = @()
    if ($rawScenario.PSObject.Properties['SignIns']) {
        $signIns = @($rawScenario.SignIns) | Where-Object { $_ }
    }

    $registrations = @()
    if ($rawScenario.PSObject.Properties['Registrations']) {
        $registrations = @($rawScenario.Registrations) | Where-Object { $_ }
    }

    $roleAssignments = @()
    if ($rawScenario.PSObject.Properties['RoleAssignments']) {
        $roleAssignments = @($rawScenario.RoleAssignments) | Where-Object { $_ }
    }

    $bestPracticeNotes = @()

    if (-not $OutputDirectory) {
        $moduleRoot = Split-Path -Parent $PSScriptRoot
        $OutputDirectory = Join-Path -Path $moduleRoot -ChildPath 'reports'
    }

    if (-not (Test-Path -Path $OutputDirectory)) {
        Write-Verbose ("Creating output directory '{0}'." -f $OutputDirectory)
        New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
    }

    $ticketDirectory = Join-Path -Path $OutputDirectory -ChildPath 'tickets'
    $notificationDirectory = Join-Path -Path $OutputDirectory -ChildPath 'notifications'
    foreach ($dir in @($ticketDirectory, $notificationDirectory)) {
        if (-not (Test-Path -Path $dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
        }
    }

    Write-Progress -Activity 'Processing scenario' -Status 'Evaluating detections' -PercentComplete 20

    $referenceTime = Get-Date
    if ($rawScenario.PSObject.Properties['ReferenceTime'] -and $rawScenario.ReferenceTime) {
        $referenceTime = [datetime]$rawScenario.ReferenceTime
    }
    elseif ($signIns.Count -gt 0) {
        $referenceTime = ($signIns | ForEach-Object { [datetime]$_.CreatedDateTime } | Sort-Object)[-1]
    }

    $allDetections = @()
    if ($registrations.Count -gt 0) {
        $allDetections += Invoke-MfaDetectionDormantMethod -RegistrationData $registrations -ReferenceTime $referenceTime
    }
    if ($signIns.Count -gt 0) {
        $allDetections += Invoke-MfaDetectionHighRiskSignin -SignInData $signIns -ReferenceTime $referenceTime
        $allDetections += Invoke-MfaDetectionRepeatedMfaFailure -SignInData $signIns -ReferenceTime $referenceTime
        $allDetections += Invoke-MfaDetectionImpossibleTravelSuccess -SignInData $signIns -ReferenceTime $referenceTime
    }
    if ($roleAssignments.Count -gt 0) {
        $allDetections += Invoke-MfaDetectionPrivilegedRoleNoMfa -RoleAssignments $roleAssignments -RegistrationData $registrations
    }
    if ($signIns.Count -gt 0 -or $registrations.Count -gt 0) {
        $allDetections += Invoke-MfaSuspiciousActivityScore -SignInData $signIns -RegistrationData $registrations -ReferenceTime $referenceTime
    }

    $allDetections = @($allDetections | Where-Object { $_ })
    Write-Verbose ("Detections discovered: {0}" -f $allDetections.Count)

    $formatIdentityList = {
        param([System.Collections.IEnumerable] $Items)

        $values = @()
        foreach ($item in $Items) {
            if ($null -ne $item -and $item -ne '') {
                $values += [string]$item
            }
        }

        if ($values.Count -eq 0) {
            return ''
        }

        $unique = $values | Sort-Object -Unique
        if ($unique.Count -le 3) {
            return $unique -join ', '
        }

        return (($unique[0..2] -join ', ') + ', …')
    }

    if ($registrations.Count -gt 0) {
        $nonAuthenticatorDefaults = @($registrations | Where-Object {
            $_ -and $_.IsDefault -and ([string]$_.MethodType -ne 'microsoftAuthenticatorAuthenticationMethod')
        })

        if ($nonAuthenticatorDefaults.Count -gt 0) {
            $affectedUsers = $nonAuthenticatorDefaults | ForEach-Object { $_.UserPrincipalName } | Where-Object { $_ } | Sort-Object -Unique
            $userSummary = & $formatIdentityList $affectedUsers

            $friendlyMethods = @{
                'smsAuthenticationMethod'                = 'SMS'
                'voiceAuthenticationMethod'              = 'Voice call'
                'temporaryAccessPassAuthenticationMethod'= 'Temporary Access Pass'
                'softwareOathAuthenticationMethod'       = 'Software OTP'
                'emailAuthenticationMethod'              = 'Email OTP'
                'fido2AuthenticationMethod'              = 'FIDO2 security key'
                'passwordlessPhoneSignInMethod'          = 'Authenticator passwordless (legacy)'
            }

            $methodSummary = ($nonAuthenticatorDefaults | Group-Object -Property MethodType | ForEach-Object {
                $type = if ($_.Name) { [string]$_.Name } else { 'Unknown' }
                $label = if ($friendlyMethods.ContainsKey($type)) { $friendlyMethods[$type] } else { $type }
                "{0} ({1})" -f $label, $_.Count
            }) -join ', '

            $privilegedUsers = @()
            if ($roleAssignments.Count -gt 0) {
                $privilegedUsers = $roleAssignments | ForEach-Object {
                    if ($_.PSObject.Properties['UserPrincipalName']) { [string]$_.UserPrincipalName }
                    elseif ($_.PSObject.Properties['PrincipalId']) { [string]$_.PrincipalId }
                    else { $null }
                } | Where-Object { $_ } | Sort-Object -Unique
            }

            $importance = 'High'
            if ($privilegedUsers -and -not ($affectedUsers | Where-Object { $privilegedUsers -contains $_ })) {
                $importance = 'Medium'
            }

            $summary = if ($userSummary) {
                "Default MFA methods for $userSummary rely on weaker factors ($methodSummary). Shift these identities to Microsoft Authenticator with number matching enforced via Conditional Access authentication strength."
            }
            else {
                "Default MFA methods rely on non-Authenticator factors ($methodSummary). Shift identities to Microsoft Authenticator with number matching enforced via Conditional Access authentication strength."
            }

            $bestPracticeNotes += [pscustomobject]@{
                Title      = 'Promote Microsoft Authenticator number matching'
                Importance = $importance
                Audience   = 'IAM / Conditional Access'
                Summary    = $summary
                Evidence   = if ($methodSummary) { "Current defaults: $methodSummary" } else { $null }
            }
        }
    }

    $fatigueDetections = @($allDetections | Where-Object {
        $_.PSObject.Properties['DetectionId'] -and $_.DetectionId -eq 'MFA-DET-004'
    })
    if ($fatigueDetections.Count -gt 0) {
        $fatigueUsers = $fatigueDetections | ForEach-Object { $_.UserPrincipalName } | Where-Object { $_ } | Sort-Object -Unique
        $userSummary = & $formatIdentityList $fatigueUsers

        $evidenceStrings = @(
            $fatigueDetections | ForEach-Object {
                if ($_.PSObject.Properties['FailureReasons'] -and $_.FailureReasons) {
                    $_.FailureReasons
                }
            }
        ) | Where-Object { $_ }

        $evidenceText = $null
        if ($evidenceStrings) {
            $flatEvidence = (($evidenceStrings -join ';') -split ';') | ForEach-Object { $_.Trim() } | Where-Object { $_ }
            if ($flatEvidence) {
                $evidenceText = "Observed failure reasons: {0}" -f (($flatEvidence | Sort-Object -Unique) -join '; ')
            }
        }

        $bestPracticeNotes += [pscustomobject]@{
            Title      = 'Enforce number matching for Microsoft Authenticator push'
            Importance = 'High'
            Audience   = 'Conditional Access owners / IAM'
            Summary    = if ($userSummary) {
                "Repeated MFA denials were detected for $userSummary. Require Microsoft Authenticator number matching via Conditional Access authentication strength to neutralize push fatigue attacks."
            }
            else {
                "Repeated MFA push denials were detected. Require Microsoft Authenticator number matching via Conditional Access authentication strength to neutralize push fatigue attacks."
            }
            Evidence   = $evidenceText
        }
    }

    Write-Progress -Activity 'Processing scenario' -Status 'Planning playbooks' -PercentComplete 50

    $playbookPlans = @()
    $playbookParams = @{
        SkipAuthorization   = $SkipAuthorization.IsPresent
        SkipGraphValidation = $true
        WhatIf              = $true
        Verbose             = $false
    }

    foreach ($detection in $allDetections) {
        if (-not $detection -or -not $detection.DetectionId) { continue }
        $plan = $null
        switch ($detection.DetectionId) {
            'MFA-DET-001' { $plan = Invoke-MfaPlaybookResetDormantMethod @playbookParams -Detection $detection }
            'MFA-DET-002' { $plan = Invoke-MfaPlaybookContainHighRiskSignin @playbookParams -Detection $detection }
            'MFA-DET-003' { $plan = Invoke-MfaPlaybookEnforcePrivilegedRoleMfa @playbookParams -Detection $detection }
            'MFA-DET-004' { $plan = Invoke-MfaPlaybookContainRepeatedFailure @playbookParams -Detection $detection }
            'MFA-DET-005' { $plan = Invoke-MfaPlaybookInvestigateImpossibleTravel @playbookParams -Detection $detection }
        }

        if ($plan) {
            $playbookPlans += $plan
        }
    }

    $scorePlaybookParams = [hashtable]$playbookParams.Clone()
    if ($scorePlaybookParams.ContainsKey('SkipGraphValidation')) {
        $scorePlaybookParams.Remove('SkipGraphValidation')
    }

    foreach ($score in $allDetections | Where-Object { $_.PSObject.Properties['Score'] }) {
        $plan = Invoke-MfaPlaybookTriageSuspiciousScore -Score $score @scorePlaybookParams
        if ($plan) {
            $playbookPlans += $plan
        }
    }

    $playbookPlans = @($playbookPlans | Where-Object { $_ })
    Write-Verbose ("Playbook plans generated: {0}" -f $playbookPlans.Count)

    Write-Progress -Activity 'Processing scenario' -Status 'Collecting playbook outputs' -PercentComplete 70

    $playbookOutputs = @()
    foreach ($plan in $playbookPlans) {
        $ticketFile = Join-Path -Path $ticketDirectory -ChildPath ("ticket-{0}-{1}.json" -f $plan.PlaybookId, ([guid]::NewGuid().ToString('N')))
        $notificationFile = Join-Path -Path $notificationDirectory -ChildPath ("notification-{0}-{1}.json" -f $plan.PlaybookId, ([guid]::NewGuid().ToString('N')))
        $playbookOutputs += Invoke-MfaPlaybookOutputs -Playbook $plan -TicketOutFile $ticketFile -NotificationOutFile $notificationFile -PassThru
    }

    $timestamp = (Get-Date).ToString('yyyyMMddTHHmmss')
    $htmlPath = Join-Path -Path $OutputDirectory -ChildPath ("scenario-report-{0}.html" -f $timestamp)
    $report = New-MfaHtmlReport -Detections $allDetections -Playbooks $playbookOutputs -BestPractices $bestPracticeNotes -Path $htmlPath -OpenInBrowser:$OpenReport

    Write-Verbose ("HTML report saved to: {0}" -f $report.Path)

    $result = [pscustomobject]@{
        ScenarioPath     = $scenarioSource
        DetectionCount   = $allDetections.Count
        PlaybookCount    = $playbookOutputs.Count
        HtmlReport       = $report.Path
        TicketOutputs    = @($playbookOutputs | ForEach-Object { $_.TicketResult.Target })
        NotificationOutputs = @($playbookOutputs | ForEach-Object { $_.NotificationResult.Target })
        OutputDirectory  = $OutputDirectory
        BestPracticeNotes = @($bestPracticeNotes)
        BestPracticeCount = @($bestPracticeNotes).Count
    }

    if ($PassThru) {
        return $result
    }
    else {
        $result.HtmlReport
    }
}

function Invoke-MfaTenantReport {
    [CmdletBinding()]
    param(
        [ValidateRange(1, 720)]
        [int] $LookbackHours = 24,
        [datetime] $ReferenceTime,
        [string[]] $UserPrincipalName,
        [string[]] $RegistrationUserPrincipalName,
        [psobject[]] $RoleAssignments,
        [switch] $IncludePrivilegedRoleAudit,
        [string] $OutputDirectory,
        [switch] $SkipAuthorization,
        [switch] $OpenReport,
        [switch] $PassThru
    )

    $graphContext = Get-MfaGraphContext
    if (-not $graphContext) {
        throw "Microsoft Graph context not found. Run Connect-MgGraph or scripts/connect-device-login.ps1 before invoking Invoke-MfaTenantReport."
    }

    $effectiveReferenceTime = if ($ReferenceTime) { $ReferenceTime } else { Get-Date }
    $lookback = [int][math]::Max(1, [math]::Abs($LookbackHours))
    $windowStart = $effectiveReferenceTime.AddHours(-$lookback)

    Write-Verbose ("Collecting Entra sign-ins from {0} to {1}." -f $windowStart.ToString('u'), $effectiveReferenceTime.ToString('u'))

    $signIns = @()
    $targetUsers = @()
    if ($UserPrincipalName) {
        $targetUsers = @($UserPrincipalName | Where-Object { $_ }) | Sort-Object -Unique
    }

    if ($targetUsers.Count -gt 0) {
        foreach ($user in $targetUsers) {
            try {
                $signIns += Get-MfaEntraSignIn -Normalize -StartTime $windowStart -EndTime $effectiveReferenceTime -UserPrincipalName $user -All
            }
            catch {
                Write-Warning ("Failed to collect sign-ins for '{0}': {1}" -f $user, $_.Exception.Message)
            }
        }
    }
    else {
        $signIns = Get-MfaEntraSignIn -Normalize -StartTime $windowStart -EndTime $effectiveReferenceTime -All
    }

    $registrationTargets = @()
    if ($signIns) {
        $registrationTargets += ($signIns | ForEach-Object { $_.UserPrincipalName } | Where-Object { $_ })
    }
    if ($UserPrincipalName) {
        $registrationTargets += $UserPrincipalName
    }
    if ($RegistrationUserPrincipalName) {
        $registrationTargets += $RegistrationUserPrincipalName
    }

    $registrationTargets = @($registrationTargets | Where-Object { $_ }) | Sort-Object -Unique

    $registrations = @()
    foreach ($target in $registrationTargets) {
        try {
            $registrations += Get-MfaEntraRegistration -UserId $target -Normalize
        }
        catch {
            Write-Warning ("Failed to retrieve MFA registrations for '{0}': {1}" -f $target, $_.Exception.Message)
        }
    }

    $roleAssignmentData = @()
    if ($RoleAssignments) {
        $roleAssignmentData = @($RoleAssignments | Where-Object { $_ })
    }
    elseif ($IncludePrivilegedRoleAudit) {
        try {
            $roleAssignmentData = Get-MfaDirectoryRoleAssignment -Normalize
        }
        catch {
            Write-Warning ("Failed to retrieve directory role assignments: {0}" -f $_.Exception.Message)
        }
    }

    $scenarioPayload = [ordered]@{
        ReferenceTime  = $effectiveReferenceTime.ToString('o')
        SignIns        = $signIns
        Registrations  = $registrations
        RoleAssignments = $roleAssignmentData
    }

    $reportParams = @{
        Scenario         = [pscustomobject]$scenarioPayload
        OutputDirectory  = $OutputDirectory
        SkipAuthorization = $SkipAuthorization
        OpenReport        = $OpenReport
        PassThru          = $true
    }

    $result = Invoke-MfaScenarioReport @reportParams

    $result | Add-Member -NotePropertyName 'LookbackHours' -NotePropertyValue $lookback -Force
    $result | Add-Member -NotePropertyName 'ReferenceTime' -NotePropertyValue $effectiveReferenceTime -Force
    $result | Add-Member -NotePropertyName 'SignInCount' -NotePropertyValue $signIns.Count -Force
    $result | Add-Member -NotePropertyName 'RegistrationCount' -NotePropertyValue $registrations.Count -Force
    $result | Add-Member -NotePropertyName 'RoleAssignmentCount' -NotePropertyValue $roleAssignmentData.Count -Force

    if ($PassThru) {
        return $result
    }

    return $result.HtmlReport
}

Export-ModuleMember -Function Invoke-MfaScenarioReport, Invoke-MfaTenantReport
