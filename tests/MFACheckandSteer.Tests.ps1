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
                param($Filter, $All, $Top)
                [pscustomobject]@{
                    Filter = $Filter
                    All    = $All
                    Top    = $Top
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
                param($UserId)
                [pscustomobject]@{ UserId = $UserId }
            }
        }

        It 'invokes Graph query for provided user' {
            $result = Get-MfaEntraRegistration -UserId 'user@contoso.com'
            $result.UserId | Should -Be 'user@contoso.com'
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
