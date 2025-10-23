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
    }
}
