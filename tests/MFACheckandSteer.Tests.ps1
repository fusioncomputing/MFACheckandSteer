Import-Module "$PSScriptRoot/../src/MFACheckandSteer.psd1" -Force

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
