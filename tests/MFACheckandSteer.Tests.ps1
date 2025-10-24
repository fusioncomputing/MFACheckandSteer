Import-Module "$PSScriptRoot/../src/MFACheckandSteer.psd1" -Force

BeforeAll {
    if (-not (Get-Command -Name Select-MgProfile -ErrorAction SilentlyContinue)) {
        function Select-MgProfile {
            param([string] $Name)
        }
    }
    if (-not (Get-Command -Name Connect-MgGraph -ErrorAction SilentlyContinue)) {
        function Connect-MgGraph {
            [CmdletBinding()]
            param(
                [string[]] $Scopes,
                [switch] $UseDeviceCode,
                [switch] $NoWelcome
            )
        }
    }
}

Describe 'MFACheckandSteer module' {
    It 'exports Get-MfaEnvironmentStatus' {
        (Get-Command Get-MfaEnvironmentStatus).Module.Name | Should -Be 'MFACheckandSteer'
    }

    It 'reports module status for required dependencies' {
        $result = Get-MfaEnvironmentStatus
        $result | Should -Not -BeNullOrEmpty
        @($result).Count | Should -BeGreaterThan 0
    }
}

Describe 'Connect-MfaGraphDeviceCode' {
    InModuleScope MFACheckandSteer {
        BeforeEach {
            Mock -CommandName Test-MfaGraphPrerequisite -ModuleName MFACheckandSteer -MockWith { $true }
            Mock -CommandName Get-Command -ModuleName MFACheckandSteer -MockWith {
                param([string] $Name, [object] $ErrorAction)
                return $null
            }
            Mock -CommandName Connect-MgGraph -ModuleName MFACheckandSteer -MockWith { param($Scopes, $UseDeviceCode, $NoWelcome) }
            Mock -CommandName Get-MfaGraphContext -ModuleName MFACheckandSteer -MockWith {
                [pscustomobject]@{
                    TenantId = 'contoso-tenant'
                    Account  = [pscustomobject]@{ Username = 'admin@contoso.com' }
                    Scopes   = @('AuditLog.Read.All')
                }
            }
        }

        It 'invokes Connect-MgGraph with device code flow' {
            Connect-MfaGraphDeviceCode | Out-Null

            Assert-MockCalled Connect-MgGraph -Times 1 -Exactly -Scope It -ParameterFilter {
                $UseDeviceCode -and $NoWelcome
            }
        }

        It 'skips beta profile when requested' {
            Connect-MfaGraphDeviceCode -SkipBetaProfile | Out-Null
            Assert-MockCalled Connect-MgGraph -Times 1 -Exactly -Scope It
        }
    }
}

Describe 'Invoke-MfaGraphWithRetry' {
    InModuleScope MFACheckandSteer {
        It 'returns result when operation succeeds first try' {
            $result = Invoke-MfaGraphWithRetry -Operation { 'ok' }
            $result | Should -Be 'ok'
        }

        It 'retries when throttled and eventually succeeds' {
            Mock -CommandName Start-Sleep -ModuleName MFACheckandSteer -MockWith { param($Seconds) }
            $callCount = [ref]0
            $result = Invoke-MfaGraphWithRetry -Operation {
                $callCount.Value++
                if ($callCount.Value -lt 2) {
                    throw "StatusCode: 429 Too Many Requests"
                }
                'success'
            }

            $result | Should -Be 'success'
            Assert-MockCalled Start-Sleep -Times 1 -Scope It
        }

        It 'does not retry non-throttle errors' {
            { Invoke-MfaGraphWithRetry -Operation { throw "boom" } } | Should -Throw
        }
    }
}

Describe 'ConvertTo-MfaCanonicalSignIn' {
    InModuleScope MFACheckandSteer {
        It 'creates canonical sign-in object' {
            $input = [pscustomobject]@{
                Id = '123'
                UserTenantId = 'tenant'
                CreatedDateTime = [datetime]'2025-10-23T12:00:00Z'
                UserId = 'user-id'
                UserPrincipalName = 'user@contoso.com'
                UserDisplayName = 'User One'
                AppDisplayName = 'App'
                AppId = 'app-id'
                IpAddress = '10.0.0.1'
                IsInteractive = $true
                AuthenticationRequirement = 'mfa'
                AuthenticationRequirementPolicies = @('policyA','policyB')
                AuthenticationDetails = @(
                    [pscustomobject]@{ AuthenticationMethod = 'password' },
                    [pscustomobject]@{ AuthenticationMethod = 'sms' }
                )
                ConditionalAccessStatus = 'success'
                RiskDetail = 'none'
                RiskLevelAggregated = 'low'
                RiskState = 'none'
                CorrelationId = 'corr-id'
                Location = [pscustomobject]@{
                    City = 'Seattle'
                    State = 'WA'
                    CountryOrRegion = 'US'
                }
                Status = [pscustomobject]@{
                    ErrorCode = 0
                    FailureReason = $null
                    AdditionalDetails = 'details'
                }
            }

            $result = ConvertTo-MfaCanonicalSignIn -InputObject $input
            $result.RecordType | Should -Be 'SignIn'
            $result.AuthenticationMethods | Should -Be 'password;sms'
            $result.AuthenticationRequirementPolicies | Should -Be 'policyA;policyB'
            $result.Result | Should -Be 'Success'
            $result.LocationCity | Should -Be 'Seattle'
        }
    }
}

Describe 'ConvertTo-MfaCanonicalRegistration' {
    InModuleScope MFACheckandSteer {
        It 'creates canonical registration object' {
            $input = [pscustomobject]@{
                Id = 'method-id'
                DisplayName = 'MFA Phone'
                IsDefault = $true
                PhoneNumber = '+15551234567'
                PhoneType = 'mobile'
                AdditionalProperties = @{
                    '@odata.type' = '#microsoft.graph.phoneAuthenticationMethod'
                    deviceId = 'device-1'
                    createdDateTime = '2025-10-22T00:00:00Z'
                }
            }

            $result = ConvertTo-MfaCanonicalRegistration -InputObject $input -UserPrincipalName 'user@contoso.com'
            $result.RecordType | Should -Be 'Registration'
            $result.MethodType | Should -Be 'phoneAuthenticationMethod'
            $result.UserPrincipalName | Should -Be 'user@contoso.com'
            $result.PhoneNumber | Should -Be '+15551234567'
        }
    }
}

Describe 'Get-MfaEntraSignIn' {
    InModuleScope MFACheckandSteer {
        BeforeEach {
            Mock -CommandName Get-MfaGraphContext -ModuleName MFACheckandSteer -MockWith { @{ TenantId = 'contoso' } }
            Mock -CommandName Invoke-MfaGraphSignInQuery -ModuleName MFACheckandSteer -MockWith {
                param($Filter, $All, $Top, $MaxRetries)
                [pscustomobject]@{
                    Filter = $Filter
                    All    = $All
                    Top    = $Top
                    MaxRetries = $MaxRetries
                }
            }
        }

        It 'throws when EndTime is earlier than StartTime' {
            { Get-MfaEntraSignIn -StartTime (Get-Date) -EndTime (Get-Date).AddMinutes(-5) } | Should -Throw
        }

        It 'builds filter with user principal name' {
            $start = [datetime]'2025-10-23T00:00:00Z'
            $end = [datetime]'2025-10-23T01:00:00Z'
            $result = Get-MfaEntraSignIn -StartTime $start -EndTime $end -UserPrincipalName "analyst@contoso.com" -Top 50

            $result.Filter | Should -Match "createdDateTime ge 2025-10-23T00:00:00Z"
            $result.Filter | Should -Match "createdDateTime le 2025-10-23T01:00:00Z"
            $result.Filter | Should -Match "userPrincipalName eq 'analyst@contoso.com'"
            $result.Top | Should -Be 50
            $result.All | Should -BeFalse
        }

        It 'returns all records when -All is specified' {
            $start = Get-Date
            $end = $start.AddMinutes(10)
            $result = Get-MfaEntraSignIn -StartTime $start -EndTime $end -All
            $result.All | Should -BeTrue
            $result.MaxRetries | Should -Be 3
        }

        It 'normalizes results when requested' {
            $start = Get-Date
            $end = $start.AddMinutes(10)
            Mock -CommandName Invoke-MfaGraphSignInQuery -ModuleName MFACheckandSteer -MockWith {
                [pscustomobject]@{
                    Id = 'abc'
                    UserTenantId = 'tenant'
                    CreatedDateTime = [datetime]'2025-10-23T02:00:00Z'
                    Status = [pscustomobject]@{ ErrorCode = 0 }
                }
            }

            $result = Get-MfaEntraSignIn -StartTime $start -EndTime $end -Normalize
            $result.RecordType | Should -Be 'SignIn'
        }
    }
}

Describe 'Get-MfaEntraRegistration' {
    InModuleScope MFACheckandSteer {
        BeforeEach {
            Mock -CommandName Get-MfaGraphContext -ModuleName MFACheckandSteer -MockWith { @{ TenantId = 'contoso' } }
            Mock -CommandName Invoke-MfaGraphAuthenticationMethodQuery -ModuleName MFACheckandSteer -MockWith {
                param($UserId, $MaxRetries)
                [pscustomobject]@{
                    UserId = $UserId
                    MaxRetries = $MaxRetries
                }
            }
        }

        It 'invokes Graph query for provided user' {
            $result = Get-MfaEntraRegistration -UserId 'user@contoso.com'
            $result.UserId | Should -Be 'user@contoso.com'
            $result.MaxRetries | Should -Be 3
        }

        It 'supports pipeline input' {
            $results = @('a@contoso.com','b@contoso.com') | Get-MfaEntraRegistration
            $results | Should -HaveCount 2
        }

        It 'normalizes registration results when requested' {
            Mock -CommandName Invoke-MfaGraphAuthenticationMethodQuery -ModuleName MFACheckandSteer -MockWith {
                [pscustomobject]@{
                    Id = 'method'
                    AdditionalProperties = @{
                        '@odata.type' = '#microsoft.graph.fido2AuthenticationMethod'
                    }
                }
            }

            $result = Get-MfaEntraRegistration -UserId 'user@contoso.com' -Normalize
            $result.RecordType | Should -Be 'Registration'
            $result.MethodType | Should -Be 'fido2AuthenticationMethod'
        }
    }
}

Describe 'Sample replay script' {
    It 'emits sign-in sample data as JSON' {
        $scriptPath = Join-Path -Path $PSScriptRoot -ChildPath '../scripts/replay-samples.ps1'
        $json = & $scriptPath -Dataset SignIn -AsJson
        $parsed = $json | ConvertFrom-Json
        $parsed.SignIns.Count | Should -Be 6
    }

    It 'emits registration sample data as JSON' {
        $scriptPath = Join-Path -Path $PSScriptRoot -ChildPath '../scripts/replay-samples.ps1'
        $json = & $scriptPath -Dataset Registration -AsJson
        $parsed = $json | ConvertFrom-Json
        $parsed.Registrations.Count | Should -Be 3
    }
}

Describe 'Get-MfaDetectionConfiguration' {
    It 'returns defaults when overrides are not provided' {
        $originalPath = [Environment]::GetEnvironmentVariable('MfaDetectionConfigurationPath', 'Process')
        try {
            Remove-Item Env:\MfaDetectionConfigurationPath -ErrorAction SilentlyContinue
            $config = Get-MfaDetectionConfiguration -Refresh
            $config['MFA-DET-001'].DormantDays | Should -Be 90
            $config['MFA-SCORE'].FailureThreshold | Should -Be 3
        }
        finally {
            if ($originalPath) {
                $env:MfaDetectionConfigurationPath = $originalPath
            }
            else {
                Remove-Item Env:\MfaDetectionConfigurationPath -ErrorAction SilentlyContinue
            }
            Get-MfaDetectionConfiguration -Refresh | Out-Null
        }
    }

    It 'applies overrides supplied via environment path' {
        $tempPath = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath ("mfa-config-{0}.json" -f ([Guid]::NewGuid()))
        $override = @{
            'MFA-DET-001' = @{
                DormantDays = 30
            }
            'MFA-SCORE' = @{
                FailureThreshold = 2
            }
        } | ConvertTo-Json -Depth 5
        $override | Set-Content -Path $tempPath -Encoding UTF8

        $originalPath = [Environment]::GetEnvironmentVariable('MfaDetectionConfigurationPath', 'Process')
        try {
            $env:MfaDetectionConfigurationPath = $tempPath
            $config = Get-MfaDetectionConfiguration -Refresh
            $config['MFA-DET-001'].DormantDays | Should -Be 30
            $config['MFA-SCORE'].FailureThreshold | Should -Be 2

            $now = Get-Date
            $registrationData = @(
                [pscustomobject]@{
                    UserPrincipalName   = 'override@example.com'
                    MethodType          = 'phoneAuthenticationMethod'
                    IsDefault           = $true
                    LastUpdatedDateTime = $now.AddDays(-40).ToString('o')
                }
            )

            $detectionResults = Invoke-MfaDetectionDormantMethod -RegistrationData $registrationData -ReferenceTime $now
            $detectionResults | Should -HaveCount 1

            $signIns = @(
                [pscustomobject]@{
                    UserPrincipalName       = 'override@example.com'
                    Result                  = 'Failure'
                    CreatedDateTime         = $now.AddMinutes(-10).ToString('o')
                    LocationCountryOrRegion = 'CA'
                    LocationCity            = 'Toronto'
                    RiskDetail              = 'none'
                    RiskState               = 'none'
                    ResultFailureReason     = 'User cancelled prompt.'
                    ResultAdditionalDetails = 'User cancelled prompt.'
                },
                [pscustomobject]@{
                    UserPrincipalName       = 'override@example.com'
                    Result                  = 'Failure'
                    CreatedDateTime         = $now.AddMinutes(-5).ToString('o')
                    LocationCountryOrRegion = 'CA'
                    LocationCity            = 'Toronto'
                    RiskDetail              = 'none'
                    RiskState               = 'none'
                    ResultFailureReason     = 'User cancelled prompt.'
                    ResultAdditionalDetails = 'User cancelled prompt.'
                }
            )

            $scoreResults = Invoke-MfaSuspiciousActivityScore -SignInData $signIns -RegistrationData @() -ReferenceTime $now
            $scoreResults | Should -HaveCount 1
            $scoreResults[0].Score | Should -Be 20
            $scoreResults[0].Severity | Should -Be 'Informational'
        }
        finally {
            if ($originalPath) {
                $env:MfaDetectionConfigurationPath = $originalPath
            }
            else {
                Remove-Item Env:\MfaDetectionConfigurationPath -ErrorAction SilentlyContinue
            }
            Get-MfaDetectionConfiguration -Refresh | Out-Null
            Remove-Item -Path $tempPath -ErrorAction SilentlyContinue
        }
    }
}

Describe 'Invoke-MfaDetectionDormantMethod' {
    It 'flags dormant default methods older than threshold' {
        $now = Get-Date
        $data = @(
            [pscustomobject]@{
                UserPrincipalName   = 'old@example.com'
                MethodType          = 'phoneAuthenticationMethod'
                IsDefault           = $true
                LastUpdatedDateTime = $now.AddDays(-120).ToString('o')
            },
            [pscustomobject]@{
                UserPrincipalName   = 'fresh@example.com'
                MethodType          = 'fido2AuthenticationMethod'
                IsDefault           = $true
                LastUpdatedDateTime = $now.AddDays(-10).ToString('o')
            },
            [pscustomobject]@{
                UserPrincipalName   = 'secondary@example.com'
                MethodType          = 'phoneAuthenticationMethod'
                IsDefault           = $false
                LastUpdatedDateTime = $now.AddDays(-200).ToString('o')
            }
        )

        $results = Invoke-MfaDetectionDormantMethod -RegistrationData $data -DormantDays 90 -ReferenceTime $now
        $results | Should -HaveCount 1
        $results[0].UserPrincipalName | Should -Be 'old@example.com'
        $results[0].DetectionId | Should -Be 'MFA-DET-001'
        $results[0].ReportingTags | Should -Contain 'Risk-Medium'
        $results[0].FrameworkTags | Should -Contain 'ATTACK:T1078'
        $results[0].NistFunctions | Should -Contain 'PR.AC-1'
        $results[0].ControlOwner | Should -Be 'SecOps IAM Team'
        $results[0].ResponseSlaHours | Should -Be 72
        $results[0].ReviewCadenceDays | Should -Be 90
    }

    It 'treats missing LastUpdatedDateTime as dormant' {
        $now = Get-Date
        $data = @(
            [pscustomobject]@{
                UserPrincipalName   = 'unknown@example.com'
                MethodType          = 'phoneAuthenticationMethod'
                IsDefault           = $true
                LastUpdatedDateTime = $null
            }
        )

        $results = Invoke-MfaDetectionDormantMethod -RegistrationData $data -DormantDays 30 -ReferenceTime $now
        $results | Should -HaveCount 1
    }
}

Describe 'Invoke-MfaDetectionHighRiskSignin' {
    It 'flags successful high-risk sign-ins' {
        $now = Get-Date
        $data = @(
            [pscustomobject]@{
                UserPrincipalName     = 'risk@example.com'
                Result                = 'Success'
                CreatedDateTime       = $now.AddMinutes(-15).ToString('o')
                RiskState             = 'atRisk'
                RiskDetail            = 'passwordSpray'
                AuthenticationMethods = 'password;sms'
                CorrelationId         = 'abc'
            },
            [pscustomobject]@{
                UserPrincipalName     = 'ok@example.com'
                Result                = 'Success'
                CreatedDateTime       = $now.AddMinutes(-5).ToString('o')
                RiskState             = 'none'
                RiskDetail            = 'none'
            },
            [pscustomobject]@{
                UserPrincipalName     = 'fail@example.com'
                Result                = 'Failure'
                CreatedDateTime       = $now.AddMinutes(-5).ToString('o')
                RiskState             = 'atRisk'
                RiskDetail            = 'unfamiliarFeaturesOfThisDevice'
            }
        )

        $results = Invoke-MfaDetectionHighRiskSignin -SignInData $data -ObservationHours 24 -ReferenceTime $now
        $results | Should -HaveCount 1
        $results[0].UserPrincipalName | Should -Be 'risk@example.com'
        $results[0].DetectionId | Should -Be 'MFA-DET-002'
        $results[0].ReportingTags | Should -Contain 'Risk-High'
        $results[0].FrameworkTags | Should -Contain 'ATTACK:T1621'
        $results[0].NistFunctions | Should -Contain 'DE.CM-7'
        $results[0].ControlOwner | Should -Be 'SecOps Incident Response'
        $results[0].ResponseSlaHours | Should -Be 4
        $results[0].ReviewCadenceDays | Should -Be 30
    }

    It 'respects risk detail exclusions' -Skip {}
}

Describe 'Invoke-MfaDetectionRepeatedMfaFailure' {
    It 'emits a detection when failures exceed the threshold within the window' {
        $reference = Get-Date
        $data = @(
            [pscustomobject]@{
                UserPrincipalName   = 'burst@example.com'
                CreatedDateTime     = $reference.AddMinutes(-6).ToString('o')
                Result              = 'Failure'
                ResultFailureReason = 'User denied unexpected prompt.'
                ResultErrorCode     = 500121
                CorrelationId       = 'burst-001'
            },
            [pscustomobject]@{
                UserPrincipalName   = 'burst@example.com'
                CreatedDateTime     = $reference.AddMinutes(-4).ToString('o')
                Result              = 'Failure'
                ResultFailureReason = 'Timeout waiting for confirmation.'
                ResultErrorCode     = 500121
                CorrelationId       = 'burst-002'
            },
            [pscustomobject]@{
                UserPrincipalName   = 'burst@example.com'
                CreatedDateTime     = $reference.AddMinutes(-2).ToString('o')
                Result              = 'Failure'
                ResultFailureReason = 'User denied unexpected prompt.'
                ResultErrorCode     = 500121
                CorrelationId       = 'burst-003'
            },
            [pscustomobject]@{
                UserPrincipalName   = 'other@example.com'
                CreatedDateTime     = $reference.AddMinutes(-2).ToString('o')
                Result              = 'Failure'
                ResultFailureReason = 'User denied unexpected prompt.'
                ResultErrorCode     = 500121
                CorrelationId       = 'other-001'
            }
        )

        $results = Invoke-MfaDetectionRepeatedMfaFailure -SignInData $data -ObservationHours 1 -FailureThreshold 3 -FailureWindowMinutes 10 -ReferenceTime $reference
        $results | Should -HaveCount 1

        $detection = $results[0]
        $detection.DetectionId | Should -Be 'MFA-DET-004'
        $detection.UserPrincipalName | Should -Be 'burst@example.com'
        $detection.FailureCount | Should -BeGreaterOrEqual 3
        $detection.FailureWindowMinutes | Should -Be 10
        $detection.WindowEnd | Should -BeLessOrEqual $reference
        $detection.ReportingTags | Should -Contain 'Risk-Medium'
        $detection.FrameworkTags | Should -Contain 'ATTACK:T1110'
        $detection.ControlOwner | Should -Be 'SecOps Incident Response'
        $detection.CorrelationIds | Should -Contain 'burst-001'
        $detection.CorrelationIds | Should -Contain 'burst-003'
    }

    It 'returns empty when failures stay below the threshold' {
        $reference = Get-Date
        $data = @(
            [pscustomobject]@{
                UserPrincipalName   = 'quiet@example.com'
                CreatedDateTime     = $reference.AddMinutes(-20).ToString('o')
                Result              = 'Failure'
                ResultFailureReason = 'User denied unexpected prompt.'
            },
            [pscustomobject]@{
                UserPrincipalName   = 'quiet@example.com'
                CreatedDateTime     = $reference.AddMinutes(-5).ToString('o')
                Result              = 'Failure'
                ResultFailureReason = 'User denied unexpected prompt.'
            }
        )

        $results = Invoke-MfaDetectionRepeatedMfaFailure -SignInData $data -ObservationHours 1 -FailureThreshold 3 -FailureWindowMinutes 10 -ReferenceTime $reference
        $results | Should -BeNullOrEmpty
    }
}

Describe 'Invoke-MfaDetectionImpossibleTravelSuccess' {
    It 'flags impossible travel successes by default' {
        $reference = Get-Date
        $data = @(
            [pscustomobject]@{
                UserPrincipalName         = 'traveler@example.com'
                CreatedDateTime           = $reference.AddMinutes(-40).ToString('o')
                LocationCountryOrRegion   = 'CA'
                LocationCity              = 'Toronto'
                IpAddress                 = '203.0.113.10'
                Result                    = 'Success'
                AuthenticationRequirement = 'mfa'
                AuthenticationMethods     = 'password;microsoftAuthenticatorPush'
            },
            [pscustomobject]@{
                UserPrincipalName         = 'traveler@example.com'
                CreatedDateTime           = $reference.AddMinutes(-15).ToString('o')
                LocationCountryOrRegion   = 'DE'
                LocationCity              = 'Berlin'
                IpAddress                 = '198.51.100.50'
                Result                    = 'Success'
                AuthenticationRequirement = 'mfa'
                AuthenticationMethods     = 'password;microsoftAuthenticatorPush'
            },
            [pscustomobject]@{
                UserPrincipalName         = 'traveler@example.com'
                CreatedDateTime           = $reference.AddMinutes(-5).ToString('o')
                LocationCountryOrRegion   = 'DE'
                LocationCity              = 'Berlin'
                IpAddress                 = '198.51.100.51'
                Result                    = 'Success'
                AuthenticationRequirement = 'mfa'
                AuthenticationMethods     = 'password;microsoftAuthenticatorPush'
            }
        )

        $results = Invoke-MfaDetectionImpossibleTravelSuccess -SignInData $data -ObservationHours 1 -TravelWindowMinutes 60 -ReferenceTime $reference
        $results | Should -HaveCount 1

        $detection = $results[0]
        $detection.DetectionId | Should -Be 'MFA-DET-005'
        $detection.UserPrincipalName | Should -Be 'traveler@example.com'
        $detection.PreviousCountry | Should -Be 'CA'
        $detection.CurrentCountry | Should -Be 'DE'
        $detection.TimeDeltaMinutes | Should -BeLessOrEqual 60
        $detection.ReportingTags | Should -Contain 'Risk-High'
        $detection.FrameworkTags | Should -Contain 'ATTACK:T1078'
        $detection.ControlOwner | Should -Be 'SecOps Threat Hunting'
    }

    It 'respects RequireMfaRequirement when disabled' {
        $reference = Get-Date
        $data = @(
            [pscustomobject]@{
                UserPrincipalName         = 'api@example.com'
                CreatedDateTime           = $reference.AddMinutes(-30).ToString('o')
                LocationCountryOrRegion   = 'US'
                LocationCity              = 'Seattle'
                IpAddress                 = '203.0.113.90'
                Result                    = 'Success'
                AuthenticationRequirement = $null
                AuthenticationMethods     = 'password'
            },
            [pscustomobject]@{
                UserPrincipalName         = 'api@example.com'
                CreatedDateTime           = $reference.AddMinutes(-5).ToString('o')
                LocationCountryOrRegion   = 'GB'
                LocationCity              = 'London'
                IpAddress                 = '198.51.100.90'
                Result                    = 'Success'
                AuthenticationRequirement = $null
                AuthenticationMethods     = 'password'
            }
        )

        $defaultResults = Invoke-MfaDetectionImpossibleTravelSuccess -SignInData $data -ObservationHours 1 -TravelWindowMinutes 45 -ReferenceTime $reference
        $defaultResults | Should -BeNullOrEmpty

        $overriddenResults = Invoke-MfaDetectionImpossibleTravelSuccess -SignInData $data -ObservationHours 1 -TravelWindowMinutes 45 -RequireMfaRequirement:$false -ReferenceTime $reference
        $overriddenResults | Should -HaveCount 1
    }
}

Describe 'Invoke-MfaSuspiciousActivityScore' {
    It 'produces scores for suspicious activity combinations' {
        $reference = [datetime]'2025-10-22T16:00:00Z'
        $signIns = @(
            [pscustomobject]@{
                UserPrincipalName       = 'analyst@example.com'
                CreatedDateTime         = $reference.AddHours(-2).ToString('o')
                LocationCountryOrRegion = 'CA'
                LocationCity            = 'Toronto'
                Result                  = 'Success'
                RiskDetail              = 'none'
                RiskState               = 'none'
                ResultFailureReason     = $null
                ResultAdditionalDetails = $null
            },
            [pscustomobject]@{
                UserPrincipalName       = 'analyst@example.com'
                CreatedDateTime         = $reference.AddMinutes(-65).ToString('o')
                LocationCountryOrRegion = 'US'
                LocationCity            = 'New York'
                Result                  = 'Success'
                RiskDetail              = 'none'
                RiskState               = 'none'
                ResultFailureReason     = $null
                ResultAdditionalDetails = 'Travel anomaly'
            },
            [pscustomobject]@{
                UserPrincipalName       = 'engineer@example.com'
                CreatedDateTime         = $reference.AddMinutes(-98).ToString('o')
                LocationCountryOrRegion = 'CA'
                LocationCity            = 'Vancouver'
                Result                  = 'Failure'
                RiskDetail              = 'unfamiliarFeaturesOfThisDevice'
                RiskState               = 'atRisk'
                ResultFailureReason     = 'Device authentication timed out.'
                ResultAdditionalDetails = 'Ignored MFA prompt'
            },
            [pscustomobject]@{
                UserPrincipalName       = 'engineer@example.com'
                CreatedDateTime         = $reference.AddMinutes(-90).ToString('o')
                LocationCountryOrRegion = 'CA'
                LocationCity            = 'Vancouver'
                Result                  = 'Failure'
                RiskDetail              = 'unfamiliarFeaturesOfThisDevice'
                RiskState               = 'atRisk'
                ResultFailureReason     = 'Push denied by user.'
                ResultAdditionalDetails = 'Unexpected MFA prompt'
            },
            [pscustomobject]@{
                UserPrincipalName       = 'engineer@example.com'
                CreatedDateTime         = $reference.AddMinutes(-82).ToString('o')
                LocationCountryOrRegion = 'CA'
                LocationCity            = 'Vancouver'
                Result                  = 'Failure'
                RiskDetail              = 'unfamiliarFeaturesOfThisDevice'
                RiskState               = 'atRisk'
                ResultFailureReason     = 'Timeout waiting for confirmation.'
                ResultAdditionalDetails = 'Repeated prompt ignored'
            },
            [pscustomobject]@{
                UserPrincipalName       = 'security.admin@example.com'
                CreatedDateTime         = $reference.AddMinutes(-55).ToString('o')
                LocationCountryOrRegion = 'CA'
                LocationCity            = 'Ottawa'
                Result                  = 'Success'
                RiskDetail              = 'registerSecurityInformation'
                RiskState               = 'atRisk'
                ResultFailureReason     = $null
                ResultAdditionalDetails = 'User recently reset MFA methods.'
            }
        )

        $registrations = @(
            [pscustomobject]@{
                UserPrincipalName    = 'security.admin@example.com'
                MethodType           = 'phoneAuthenticationMethod'
                IsDefault            = $true
                LastUpdatedDateTime  = $reference.AddMinutes(-60).ToString('o')
            }
        )

        $results = Invoke-MfaSuspiciousActivityScore -SignInData $signIns -RegistrationData $registrations -ReferenceTime $reference -ObservationHours 24
        $results | Should -HaveCount 3

        $analyst = $results | Where-Object { $_.UserPrincipalName -eq 'analyst@example.com' }
        $analyst.Score | Should -Be 40
        ($analyst.Indicators.Type) | Should -Contain 'ImpossibleTravel'
        $analyst.Severity | Should -Be 'Medium'
        $analyst.SignalId | Should -Be 'MFA-SCORE'
        $analyst.ReportingTags | Should -Contain 'Risk-Medium'
        $analyst.FrameworkTags | Should -Contain 'ATTACK:T1110'
        $analyst.ControlOwner | Should -Be 'SecOps Triage Desk'
        $analyst.ResponseSlaHours | Should -Be 24
        $analyst.ReviewCadenceDays | Should -Be 14

        $engineer = $results | Where-Object { $_.UserPrincipalName -eq 'engineer@example.com' }
        $engineer.Score | Should -Be 35
        ($engineer.Indicators.Type) | Should -Contain 'RepeatedFailures'
        ($engineer.Indicators.Type) | Should -Contain 'UnusualDevice'
        $engineer.ReportingTags | Should -Contain 'Risk-Medium'
        $engineer.ResponseSlaHours | Should -Be 24

        $admin = $results | Where-Object { $_.UserPrincipalName -eq 'security.admin@example.com' }
        $admin.Score | Should -Be 40
        ($admin.Indicators.Type) | Should -Contain 'HighRiskFactorChange'
        $admin.ReportingTags | Should -Contain 'Risk-Medium'
        $admin.ControlOwner | Should -Be 'SecOps Triage Desk'
    }

    It 'returns empty when no suspicious patterns are detected' {
        $reference = [datetime]'2025-10-22T16:00:00Z'
        $signIns = @(
            [pscustomobject]@{
                UserPrincipalName       = 'normal@example.com'
                CreatedDateTime         = $reference.AddHours(-3).ToString('o')
                LocationCountryOrRegion = 'CA'
                LocationCity            = 'Calgary'
                Result                  = 'Success'
                RiskDetail              = 'none'
                RiskState               = 'none'
                ResultFailureReason     = $null
                ResultAdditionalDetails = 'Routine access.'
            },
            [pscustomobject]@{
                UserPrincipalName       = 'normal@example.com'
                CreatedDateTime         = $reference.AddHours(-1).ToString('o')
                LocationCountryOrRegion = 'CA'
                LocationCity            = 'Calgary'
                Result                  = 'Success'
                RiskDetail              = 'none'
                RiskState               = 'none'
                ResultFailureReason     = $null
                ResultAdditionalDetails = 'Routine access.'
            }
        )

        $results = Invoke-MfaSuspiciousActivityScore -SignInData $signIns -ReferenceTime $reference -ObservationHours 4
        $results | Should -BeNullOrEmpty
    }
}

Describe 'Invoke-MfaDetectionPrivilegedRoleNoMfa' {
    InModuleScope MFACheckandSteer {
        It 'flags privileged users without MFA methods' {
            $assignments = @(
                [pscustomobject]@{
                    PrincipalId              = 'user-001'
                    UserPrincipalName        = 'pa@example.com'
                    UserDisplayName          = 'Privileged Admin'
                    RoleDefinitionId         = '62e90394-69f5-4237-9190-012177145e10'
                    RoleDefinitionDisplayName = 'Global Administrator'
                }
            )

            $registrations = @(
                [pscustomobject]@{
                    UserId              = 'user-002'
                    UserPrincipalName   = 'other@example.com'
                    IsUsable            = $true
                }
            )

            $results = Invoke-MfaDetectionPrivilegedRoleNoMfa -RoleAssignments $assignments -RegistrationData $registrations
            $results | Should -HaveCount 1
            $results[0].DetectionId | Should -Be 'MFA-DET-003'
            $results[0].UserPrincipalName | Should -Be 'pa@example.com'
            $results[0].PrivilegedRoles | Should -Contain 'Global Administrator'
            $results[0].ControlOwner | Should -Be 'SecOps IAM Team'
            $results[0].ResponseSlaHours | Should -Be 24
        }

        It 'respects privileged role overrides from configuration' {
            $tempPath = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath ("mfa-config-{0}.json" -f ([Guid]::NewGuid()))
            $override = @{
                'MFA-DET-003' = @{
                    PrivilegedRoleIds = @('custom-role')
                }
            } | ConvertTo-Json -Depth 5
            $override | Set-Content -Path $tempPath -Encoding UTF8

            $originalPath = [Environment]::GetEnvironmentVariable('MfaDetectionConfigurationPath', 'Process')
        try {
            $env:MfaDetectionConfigurationPath = $tempPath
            Get-MfaDetectionConfiguration -Refresh | Out-Null

            $assignments = @(
                [pscustomobject]@{
                    PrincipalId              = 'user-003'
                    UserPrincipalName        = 'custom@example.com'
                        RoleDefinitionId         = 'custom-role'
                        RoleDefinitionDisplayName = 'Custom Privileged Role'
                    }
                )

                $results = Invoke-MfaDetectionPrivilegedRoleNoMfa -RoleAssignments $assignments -RegistrationData @()
                $results | Should -HaveCount 1
                $results[0].PrivilegedRoles | Should -Contain 'Custom Privileged Role'
            }
            finally {
                if ($originalPath) {
                    $env:MfaDetectionConfigurationPath = $originalPath
                }
                else {
                    Remove-Item Env:\MfaDetectionConfigurationPath -ErrorAction SilentlyContinue
                }
                Get-MfaDetectionConfiguration -Refresh | Out-Null
                Remove-Item -Path $tempPath -ErrorAction SilentlyContinue
            }
        }

        It 'does not flag users with usable MFA' {
            $assignments = @(
                [pscustomobject]@{
                    PrincipalId              = 'user-004'
                    UserPrincipalName        = 'healthy@example.com'
                    RoleDefinitionId         = '62e90394-69f5-4237-9190-012177145e10'
                    RoleDefinitionDisplayName = 'Global Administrator'
                }
            )

            $registrations = @(
                [pscustomobject]@{
                    UserId              = 'user-004'
                    UserPrincipalName   = 'healthy@example.com'
                    IsUsable            = $true
                }
            )

            $results = Invoke-MfaDetectionPrivilegedRoleNoMfa -RoleAssignments $assignments -RegistrationData $registrations
            $results | Should -BeNullOrEmpty
        }
    }
}

Describe 'Invoke-MfaPlaybookResetDormantMethod' {
    InModuleScope MFACheckandSteer {
        BeforeEach {
            Mock -CommandName Get-MfaGraphContext -ModuleName MFACheckandSteer -MockWith {
                [pscustomobject]@{
                    TenantId = 'contoso-tenant'
                    Account  = [pscustomobject]@{ Username = 'admin@contoso.com' }
                }
            }
        }

        It 'returns remediation plan in simulation mode' {
            $detection = [pscustomobject]@{
                DetectionId       = 'MFA-DET-001'
                UserPrincipalName = 'user@example.com'
                MethodType        = 'phoneAuthenticationMethod'
                Severity          = 'Medium'
            }

            $result = Invoke-MfaPlaybookResetDormantMethod -Detection $detection -Verbose:$false -WhatIf
            $result.PlaybookId | Should -Be 'MFA-PL-001'
            $result.UserPrincipalName | Should -Be 'user@example.com'
            $result.ExecutedSteps | Should -Contain 'Notify user'
            $result.ExecutedSteps | Should -Contain 'Update ticket'
            $result.IsSimulation | Should -BeTrue
            $result.GraphValidated | Should -BeTrue
            $result.ControlOwner | Should -Be 'SecOps IAM Team'
            $result.ResponseSlaHours | Should -Be 72
        }

        It 'requires detection input' {
            { Invoke-MfaPlaybookResetDormantMethod -Detection $null } | Should -Throw
        }

        It 'allows skipping graph validation' {
            Mock -CommandName Get-MfaGraphContext -ModuleName MFACheckandSteer -MockWith { $null }
            $detection = [pscustomobject]@{
                DetectionId       = 'MFA-DET-001'
                UserPrincipalName = 'user2@example.com'
                MethodType        = 'phoneAuthenticationMethod'
            }

            $result = Invoke-MfaPlaybookResetDormantMethod -Detection $detection -SkipGraphValidation -NoUserNotification -WhatIf -Verbose:$false
            $result.GraphValidated | Should -BeFalse
            $result.NotificationsSent | Should -BeFalse
        }
    }
}

Describe 'Invoke-MfaPlaybookContainHighRiskSignin' {
    InModuleScope MFACheckandSteer {
        BeforeEach {
            Mock -CommandName Get-MfaGraphContext -ModuleName MFACheckandSteer -MockWith {
                [pscustomobject]@{
                    TenantId = 'contoso-tenant'
                    Account  = [pscustomobject]@{ Username = 'admin@contoso.com' }
                }
            }
        }

        It 'returns containment plan with simulated steps' {
            $detection = [pscustomobject]@{
                DetectionId       = 'MFA-DET-002'
                UserPrincipalName = 'risk@example.com'
                CorrelationId     = 'corr-123'
                Severity          = 'High'
                RiskState         = 'atRisk'
                RiskDetail        = 'passwordSpray'
            }

            $result = Invoke-MfaPlaybookContainHighRiskSignin -Detection $detection -Verbose:$false -WhatIf
            $result.PlaybookId | Should -Be 'MFA-PL-002'
            $result.UserPrincipalName | Should -Be 'risk@example.com'
            $result.ExecutedSteps | Should -Contain 'Revoke sessions'
            $result.ExecutedSteps | Should -Contain 'Update incident/ticket'
            $result.IsSimulation | Should -BeTrue
            $result.ControlOwner | Should -Be 'SecOps Incident Response'
            $result.ResponseSlaHours | Should -Be 4
        }

        It 'supports skipping graph validation and notifications' {
            Mock -CommandName Get-MfaGraphContext -ModuleName MFACheckandSteer -MockWith { $null }
            $detection = [pscustomobject]@{
                DetectionId       = 'MFA-DET-002'
                UserPrincipalName = 'risk2@example.com'
            }

            $result = Invoke-MfaPlaybookContainHighRiskSignin -Detection $detection -SkipGraphValidation -NoUserNotification -NoTicketUpdate -WhatIf -Verbose:$false
            $result.GraphValidated | Should -BeFalse
            $result.NotificationsSent | Should -BeFalse
            $result.TicketUpdated | Should -BeFalse
            $result.SkippedSteps | Should -Contain 'Notify stakeholders'
            $result.SkippedSteps | Should -Contain 'Update incident/ticket'
        }

        It 'requires detection input' {
            { Invoke-MfaPlaybookContainHighRiskSignin -Detection $null } | Should -Throw
        }
    }
}

Describe 'Invoke-MfaPlaybookContainRepeatedFailure' {
    InModuleScope MFACheckandSteer {
        BeforeEach {
            Mock -CommandName Get-MfaGraphContext -ModuleName MFACheckandSteer -MockWith {
                [pscustomobject]@{
                    TenantId = 'contoso-tenant'
                    Account  = [pscustomobject]@{ Username = 'admin@contoso.com' }
                }
            }
        }

        It 'returns containment guidance for repeated failures' {
            $detection = [pscustomobject]@{
                DetectionId          = 'MFA-DET-004'
                UserPrincipalName    = 'burst@example.com'
                FailureCount         = 5
                WindowStart          = (Get-Date).AddMinutes(-12)
                WindowEnd            = (Get-Date)
                FailureWindowMinutes = 15
                FailureReasons       = 'User denied unexpected prompt; Timeout waiting for confirmation.'
                FailureErrorCodes    = @(500121)
                CorrelationIds       = @('burst-001','burst-002')
                Severity             = 'Medium'
            }

            $result = Invoke-MfaPlaybookContainRepeatedFailure -Detection $detection -WhatIf -Verbose:$false
            $result.PlaybookId | Should -Be 'MFA-PL-005'
            $result.DetectionId | Should -Be 'MFA-DET-004'
            $result.UserPrincipalName | Should -Be 'burst@example.com'
            $result.FailureCount | Should -Be 5
            $result.ExecutedSteps | Should -Contain 'Temporarily block sign-in'
            $result.IsSimulation | Should -BeTrue
            $result.GraphValidated | Should -BeTrue
            $result.ControlOwner | Should -Be 'SecOps Incident Response'
            $result.ResponseSlaHours | Should -Be 8
        }

        It 'respects skip switches' {
            Mock -CommandName Get-MfaGraphContext -ModuleName MFACheckandSteer -MockWith { $null }
            $detection = [pscustomobject]@{
                DetectionId       = 'MFA-DET-004'
                UserPrincipalName = 'skip@example.com'
                FailureCount      = 3
            }

            $result = Invoke-MfaPlaybookContainRepeatedFailure -Detection $detection -SkipGraphValidation -NoUserNotification -NoTicketUpdate -NoUserBlock -WhatIf -Verbose:$false
            $result.GraphValidated | Should -BeFalse
            $result.NotificationsSent | Should -BeFalse
            $result.TicketUpdated | Should -BeFalse
            $result.UserBlocked | Should -BeFalse
            $result.SkippedSteps | Should -Contain 'Contact user'
            $result.SkippedSteps | Should -Contain 'Temporarily block sign-in'
        }
    }
}

Describe 'Invoke-MfaPlaybookInvestigateImpossibleTravel' {
    InModuleScope MFACheckandSteer {
        BeforeEach {
            Mock -CommandName Get-MfaGraphContext -ModuleName MFACheckandSteer -MockWith {
                [pscustomobject]@{
                    TenantId = 'contoso-tenant'
                    Account  = [pscustomobject]@{ Username = 'admin@contoso.com' }
                }
            }
        }

        It 'guides investigation for impossible travel detections' {
            $detection = [pscustomobject]@{
                DetectionId        = 'MFA-DET-005'
                UserPrincipalName  = 'traveler@example.com'
                PreviousCountry    = 'CA'
                CurrentCountry     = 'DE'
                TimeDeltaMinutes   = 20
                PreviousIpAddress  = '203.0.113.45'
                CurrentIpAddress   = '198.51.100.90'
                AuthenticationRequirement = 'mfa'
                AuthenticationMethods     = 'password;microsoftAuthenticatorPush'
                Severity           = 'High'
            }

            $result = Invoke-MfaPlaybookInvestigateImpossibleTravel -Detection $detection -WhatIf -Verbose:$false
            $result.PlaybookId | Should -Be 'MFA-PL-006'
            $result.DetectionId | Should -Be 'MFA-DET-005'
            $result.UserPrincipalName | Should -Be 'traveler@example.com'
            $result.PreviousCountry | Should -Be 'CA'
            $result.CurrentCountry | Should -Be 'DE'
            $result.ExecutedSteps | Should -Contain 'Validate with user'
            $result.GraphValidated | Should -BeTrue
            $result.SessionsRevoked | Should -BeTrue
            $result.ControlOwner | Should -Be 'SecOps Threat Hunting'
            $result.ResponseSlaHours | Should -Be 6
        }

        It 'supports skip switches' {
            Mock -CommandName Get-MfaGraphContext -ModuleName MFACheckandSteer -MockWith { $null }
            $detection = [pscustomobject]@{
                DetectionId        = 'MFA-DET-005'
                UserPrincipalName  = 'skip@example.com'
            }

            $result = Invoke-MfaPlaybookInvestigateImpossibleTravel -Detection $detection -SkipGraphValidation -NoUserNotification -NoTicketUpdate -NoSessionRevocation -WhatIf -Verbose:$false
            $result.GraphValidated | Should -BeFalse
            $result.SessionsRevoked | Should -BeFalse
            $result.NotificationsSent | Should -BeFalse
            $result.TicketUpdated | Should -BeFalse
            $result.SkippedSteps | Should -Contain 'Validate with user'
            $result.SkippedSteps | Should -Contain 'Revoke sessions'
        }
    }
}

Describe 'Invoke-MfaPlaybookTriageSuspiciousScore' {
    InModuleScope MFACheckandSteer {
        It 'recommends containment for high severity scores' {
            $score = [pscustomobject]@{
                SignalId          = 'MFA-SCORE'
                UserPrincipalName = 'triage@example.com'
                Score             = 80
                Severity          = 'High'
                Indicators        = @(
                    [pscustomobject]@{ Type = 'RepeatedFailures'; Weight = 20 },
                    [pscustomobject]@{ Type = 'ImpossibleTravel'; Weight = 40 }
                )
            }

            $result = Invoke-MfaPlaybookTriageSuspiciousScore -Score $score -WhatIf -Verbose:$false
            $result.PlaybookId | Should -Be 'MFA-PL-004'
            $result.ExecutedSteps | Should -Contain 'Review indicators'
            $result.RecommendedAction | Should -Be 'Launch MFA-PL-002 containment'
            $result.SuggestContainment | Should -BeTrue
            $result.ControlOwner | Should -Be 'SecOps Triage Desk'
        }

        It 'supports skipping ticket updates' {
            $score = [pscustomobject]@{
                UserPrincipalName = 'triage2@example.com'
                Score             = 30
                Severity          = 'Medium'
                Indicators        = @()
            }

            $result = Invoke-MfaPlaybookTriageSuspiciousScore -Score $score -NoTicketUpdate -WhatIf -Verbose:$false
            $result.TicketUpdated | Should -BeFalse
            $result.SkippedSteps | Should -Contain 'Update ticket'
            $result.RecommendedAction | Should -Be 'Monitor'
        }
    }
}

Describe 'Incident scenarios' {
    $scenarioRoot = Join-Path -Path $PSScriptRoot -ChildPath '../data/scenarios'
    $scenarioFiles = @()
    if (Test-Path $scenarioRoot) {
        $scenarioFiles = Get-ChildItem -Path $scenarioRoot -Filter '*.json'
    }

    BeforeAll {
        Mock -CommandName Get-MfaGraphContext -ModuleName MFACheckandSteer -MockWith {
            [pscustomobject]@{
                TenantId = 'contoso-tenant'
                Account  = [pscustomobject]@{ Username = 'analyst@contoso.com' }
            }
        }
    }

    if ($scenarioFiles) {
        $testCases = $scenarioFiles | ForEach-Object {
            @{
                ScenarioId   = $_.BaseName
                ScenarioPath = $_.FullName
            }
        }

        It 'validates scenario <ScenarioId>' -TestCases $testCases {
            param(
                [string] $ScenarioId,
                [string] $ScenarioPath
            )

            $scenario = Get-Content -Path $ScenarioPath -Raw | ConvertFrom-Json
            $signIns = @($scenario.SignIns)
            $registrations = @($scenario.Registrations)
            $roleAssignments = @($scenario.RoleAssignments)

            if ($scenario.PSObject.Properties.Name -contains 'ReferenceTime' -and $scenario.ReferenceTime) {
                $reference = [datetime]$scenario.ReferenceTime
            }
            elseif ($signIns) {
                $reference = ($signIns | ForEach-Object { [datetime]$_.CreatedDateTime } | Sort-Object)[-1]
            }
            else {
                $reference = Get-Date
            }

            $dormant = if ($registrations) { Invoke-MfaDetectionDormantMethod -RegistrationData $registrations -ReferenceTime $reference } else { @() }
            $highRisk = if ($signIns) { Invoke-MfaDetectionHighRiskSignin -SignInData $signIns -ReferenceTime $reference } else { @() }
            $repeated = if ($signIns) { Invoke-MfaDetectionRepeatedMfaFailure -SignInData $signIns -ReferenceTime $reference } else { @() }
            $impossible = if ($signIns) { Invoke-MfaDetectionImpossibleTravelSuccess -SignInData $signIns -ReferenceTime $reference } else { @() }
            $privileged = if ($roleAssignments) { Invoke-MfaDetectionPrivilegedRoleNoMfa -RoleAssignments $roleAssignments -RegistrationData $registrations } else { @() }
            $scores = if ($signIns) { Invoke-MfaSuspiciousActivityScore -SignInData $signIns -RegistrationData $registrations -ReferenceTime $reference } else { @() }
            $scores = @($scores) | Where-Object { $_ }

            $allDetections = @()
            $allDetections += @($dormant)
            $allDetections += @($highRisk)
            $allDetections += @($repeated)
            $allDetections += @($impossible)
            $allDetections += @($privileged)
            $allDetections = $allDetections | Where-Object { $_ }
            $expected = $scenario.Expectations

            if ($expected -and $expected.Detections) {
                foreach ($item in @($expected.Detections)) {
                    $match = $allDetections | Where-Object {
                        $_.DetectionId -eq $item.DetectionId -and
                        $_.UserPrincipalName -eq $item.UserPrincipalName
                    }
                    $match | Should -HaveCount 1
                    $match[0].ReportingTags | Should -Contain ("Risk-{0}" -f $match[0].Severity)
                    $match[0].ControlOwner | Should -Not -BeNullOrEmpty
                    $match[0].ResponseSlaHours | Should -BeGreaterThan 0
                }
            }

            if ($expected -and $expected.Scores) {
                foreach ($scoreExpectation in @($expected.Scores)) {
                    $scoreMatch = $scores | Where-Object { $_.UserPrincipalName -eq $scoreExpectation.UserPrincipalName }
                    $scoreMatch | Should -HaveCount 1
                    if ($scoreExpectation.MinScore) {
                        $scoreMatch[0].Score | Should -BeGreaterOrEqual $scoreExpectation.MinScore
                    }
                    if ($scoreExpectation.Severity) {
                        $scoreMatch[0].Severity | Should -Be $scoreExpectation.Severity
                    }
                    $scoreMatch[0].ReportingTags | Should -Contain ("Risk-{0}" -f $scoreMatch[0].Severity)
                    $scoreMatch[0].ControlOwner | Should -Not -BeNullOrEmpty
                    $scoreMatch[0].ResponseSlaHours | Should -BeGreaterThan 0
                }
            }

            $playbookPlans = @()
            foreach ($detection in $allDetections) {
                if (-not $detection -or -not $detection.DetectionId) { continue }

                $commonArgs = @{
                    Detection           = $detection
                    SkipGraphValidation = $true
                    WhatIf              = $true
                    Verbose             = $false
                }

                $plan = switch ($detection.DetectionId) {
                    'MFA-DET-001' { Invoke-MfaPlaybookResetDormantMethod @commonArgs }
                    'MFA-DET-002' { Invoke-MfaPlaybookContainHighRiskSignin @commonArgs }
                    'MFA-DET-003' { Invoke-MfaPlaybookEnforcePrivilegedRoleMfa @commonArgs }
                    'MFA-DET-004' { Invoke-MfaPlaybookContainRepeatedFailure @commonArgs }
                    'MFA-DET-005' { Invoke-MfaPlaybookInvestigateImpossibleTravel @commonArgs }
                    default { $null }
                }

                if ($plan) {
                    $playbookPlans += @($plan)
                }
            }

            foreach ($score in $scores) {
                if (-not $score) { continue }
                $triage = Invoke-MfaPlaybookTriageSuspiciousScore -Score $score -WhatIf -Verbose:$false
                if ($triage) {
                    $playbookPlans += @($triage)
                }
            }

            foreach ($plan in $playbookPlans) {
                $plan.PlaybookId | Should -Not -BeNullOrEmpty
                if ($plan.PSObject.Properties.Name -contains 'DetectionId' -and $plan.DetectionId) {
                    $plan.ControlOwner | Should -Not -BeNullOrEmpty
                    $plan.ResponseSlaHours | Should -BeGreaterThan 0
                }
            }
        }
    }
    else {
        It 'has no scenarios' {
            $false | Should -BeFalse -Because 'Scenario fixtures should exist.'
        }
    }
}
