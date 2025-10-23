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
        $parsed.SignIns.Count | Should -Be 2
    }

    It 'emits registration sample data as JSON' {
        $scriptPath = Join-Path -Path $PSScriptRoot -ChildPath '../scripts/replay-samples.ps1'
        $json = & $scriptPath -Dataset Registration -AsJson
        $parsed = $json | ConvertFrom-Json
        $parsed.Registrations.Count | Should -Be 2
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

        $function = (Get-Command Invoke-MfaDetectionHighRiskSignin).ScriptBlock
        $results = & $function $data 24 $now
        $results | Should -HaveCount 1
        $results[0].UserPrincipalName | Should -Be 'risk@example.com'
        $results[0].DetectionId | Should -Be 'MFA-DET-002'
    }

    It 'respects risk detail exclusions' -Skip {}
}

