[CmdletBinding(DefaultParameterSetName = 'Single')]
param(
    [Parameter(ParameterSetName = 'Single', Position = 0)]
    [string] $ScenarioId,

    [Parameter(ParameterSetName = 'List')]
    [switch] $List,

    [switch] $AsJson,
    [switch] $SimulatePlaybooks
)

$scriptRoot = Split-Path -Parent $PSCommandPath
$repoRoot = Resolve-Path (Join-Path $scriptRoot '..')
$scenarioRoot = Join-Path $repoRoot 'data/scenarios'
$modulePath = Join-Path $repoRoot 'src/MFACheckandSteer.psd1'

if (-not (Test-Path $modulePath)) {
    throw "Module manifest not found at path '$modulePath'."
}

Import-Module $modulePath -Force

if (-not (Test-Path $scenarioRoot)) {
    throw "Scenario directory not found: $scenarioRoot"
}

$scenarioFiles = Get-ChildItem -Path $scenarioRoot -Filter '*.json'
if (-not $scenarioFiles) {
    throw "No scenario files were found under $scenarioRoot."
}

if ($List) {
    $scenarioFiles |
        Sort-Object -Property BaseName |
        Select-Object @{ Name = 'ScenarioId'; Expression = { $_.BaseName } }, @{ Name = 'Name'; Expression = {
            ($content = Get-Content -Path $_.FullName -Raw | ConvertFrom-Json); $content.Name
        }} |
        Format-Table -AutoSize
    return
}

if (-not $ScenarioId) {
    $available = ($scenarioFiles | Sort-Object -Property BaseName | ForEach-Object { $_.BaseName }) -join ', '
    throw "ScenarioId is required. Available scenarios: $available"
}

$targetFile = $scenarioFiles | Where-Object { $_.BaseName -ieq $ScenarioId }
if (-not $targetFile) {
    $available = ($scenarioFiles | Sort-Object -Property BaseName | ForEach-Object { $_.BaseName }) -join ', '
    throw "Scenario '$ScenarioId' not found. Available scenarios: $available"
}

$scenario = Get-Content -Path $targetFile.FullName -Raw | ConvertFrom-Json

$signIns = @($scenario.SignIns)
$registrations = @($scenario.Registrations)
$roleAssignments = @($scenario.RoleAssignments)

$referenceTime = $null
if ($scenario.PSObject.Properties.Name -contains 'ReferenceTime' -and $scenario.ReferenceTime) {
    $referenceTime = [datetime]$scenario.ReferenceTime
}
elseif ($signIns) {
    $parsedDates = @()
    foreach ($item in $signIns) {
        try {
            $parsedDates += [datetime]$item.CreatedDateTime
        }
        catch {
        }
    }
    if ($parsedDates) {
        $referenceTime = ($parsedDates | Sort-Object)[-1]
    }
}

if (-not $referenceTime) {
    $referenceTime = Get-Date
}

$dormantDetections = @()
if ($registrations) {
    $dormantDetections = Invoke-MfaDetectionDormantMethod -RegistrationData $registrations -ReferenceTime $referenceTime
}

$highRiskDetections = @()
if ($signIns) {
    $highRiskDetections = Invoke-MfaDetectionHighRiskSignin -SignInData $signIns -ReferenceTime $referenceTime
}

$repeatedFailureDetections = @()
if ($signIns) {
    $repeatedFailureDetections = Invoke-MfaDetectionRepeatedMfaFailure -SignInData $signIns -ReferenceTime $referenceTime
}

$impossibleTravelDetections = @()
if ($signIns) {
    $impossibleTravelDetections = Invoke-MfaDetectionImpossibleTravelSuccess -SignInData $signIns -ReferenceTime $referenceTime
}

$privilegedDetections = @()
if ($roleAssignments) {
    $privilegedDetections = Invoke-MfaDetectionPrivilegedRoleNoMfa -RoleAssignments $roleAssignments -RegistrationData $registrations
}

$scores = @()
if ($signIns) {
    $scores = Invoke-MfaSuspiciousActivityScore -SignInData $signIns -RegistrationData $registrations -ReferenceTime $referenceTime
}

$payload = [ordered]@{
    ScenarioId   = $scenario.ScenarioId
    Name         = $scenario.Name
    Description  = $scenario.Description
    ReferenceTime = $referenceTime.ToString('o')
    Detections   = @($dormantDetections + $highRiskDetections + $repeatedFailureDetections + $impossibleTravelDetections + $privilegedDetections)
    Scores       = $scores
    Expectations = $scenario.Expectations
}

$playbookPlans = @()
if ($SimulatePlaybooks) {
    foreach ($detection in $payload.Detections) {
        if (-not $detection -or -not $detection.DetectionId) { continue }

        $commonArgs = @{
            Detection           = $detection
            SkipGraphValidation = $true
            WhatIf              = $true
            Verbose             = $false
        }

        switch ($detection.DetectionId) {
            'MFA-DET-001' {
                $plan = Invoke-MfaPlaybookResetDormantMethod @commonArgs
            }
            'MFA-DET-002' {
                $plan = Invoke-MfaPlaybookContainHighRiskSignin @commonArgs
            }
            'MFA-DET-003' {
                $plan = Invoke-MfaPlaybookEnforcePrivilegedRoleMfa @commonArgs
            }
            'MFA-DET-004' {
                $plan = Invoke-MfaPlaybookContainRepeatedFailure @commonArgs
            }
            'MFA-DET-005' {
                $plan = Invoke-MfaPlaybookInvestigateImpossibleTravel @commonArgs
            }
        }

        if ($plan) {
            $playbookPlans += @($plan)
        }
    }

    foreach ($score in $scores) {
        if (-not $score) { continue }
        $plan = Invoke-MfaPlaybookTriageSuspiciousScore -Score $score -WhatIf -Verbose:$false
        if ($plan) {
            $playbookPlans += @($plan)
        }
    }
}

$payload.Playbooks = $playbookPlans

if ($AsJson) {
    $payload | ConvertTo-Json -Depth 10
    return
}

Write-Host "Scenario: $($scenario.ScenarioId) - $($scenario.Name)" -ForegroundColor Cyan
Write-Host $scenario.Description -ForegroundColor Yellow
Write-Host ("Reference Time: {0}" -f $referenceTime.ToString('u')) -ForegroundColor Cyan

Write-Host "`nDetections:" -ForegroundColor Green
if ($payload.Detections) {
    $payload.Detections | Select-Object DetectionId, UserPrincipalName, Severity, ReportingTags | Format-Table -AutoSize
}
else {
    Write-Host "  (none)" -ForegroundColor DarkGray
}

Write-Host "`nSuspicious Activity Scores:" -ForegroundColor Green
if ($payload.Scores) {
    $payload.Scores | Select-Object UserPrincipalName, Score, Severity, ReportingTags | Format-Table -AutoSize
}
else {
    Write-Host "  (none)" -ForegroundColor DarkGray
}

if ($payload.Expectations) {
    Write-Host "`nExpectations (from scenario file):" -ForegroundColor Cyan
    $payload.Expectations | ConvertTo-Json -Depth 5 | Write-Output
}

Write-Host "`nUse -AsJson for machine readable output or -List to view available scenarios." -ForegroundColor Cyan

if ($SimulatePlaybooks) {
    Write-Host "`nPlaybook Plans:" -ForegroundColor Green
    if ($playbookPlans) {
        $playbookPlans | Select-Object PlaybookId, DetectionId, UserPrincipalName, ControlOwner, ResponseSlaHours | Format-Table -AutoSize
    }
    else {
        Write-Host "  (no playbooks executed)" -ForegroundColor DarkGray
    }
}
