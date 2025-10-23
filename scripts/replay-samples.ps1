[CmdletBinding()]
param(
    [ValidateSet('SignIn', 'Registration', 'All')]
    [string] $Dataset = 'All',
    [switch] $AsJson
)

$scriptRoot = Split-Path -Parent $PSCommandPath
$sampleRoot = Join-Path -Path $scriptRoot -ChildPath '..\data\samples'

function Get-SampleFile {
    param(
        [Parameter(Mandatory)]
        [string] $Name
    )

    $path = Join-Path -Path $sampleRoot -ChildPath $Name
    if (-not (Test-Path $path)) {
        throw "Sample file not found: $path"
    }

    return $path
}

function Load-SampleData {
    param(
        [Parameter(Mandatory)]
        [string] $FileName
    )

    $content = Get-Content -Path (Get-SampleFile -Name $FileName) -Raw
    $data = $content | ConvertFrom-Json
    return $data
}

Write-Host "MFA Check & Steer sample replay" -ForegroundColor Cyan
Write-Host "Loading dataset: $Dataset" -ForegroundColor Yellow

$signIns = $null
$registrations = $null

switch ($Dataset) {
    'SignIn' {
        $signIns = Load-SampleData -FileName 'entra-signins-sample.json'
    }
    'Registration' {
        $registrations = Load-SampleData -FileName 'entra-registrations-sample.json'
    }
    'All' {
        $signIns = Load-SampleData -FileName 'entra-signins-sample.json'
        $registrations = Load-SampleData -FileName 'entra-registrations-sample.json'
    }
}

if ($AsJson) {
    $output = [ordered]@{}
    if ($signIns) {
        $output['SignIns'] = $signIns
    }
    if ($registrations) {
        $output['Registrations'] = $registrations
    }

    $output | ConvertTo-Json -Depth 10
    return
}

if ($signIns) {
    Write-Host "`nSign-in events:" -ForegroundColor Green
    $signIns | Format-Table RecordType, UserPrincipalName, AppDisplayName, Result, CreatedDateTime
}

if ($registrations) {
    Write-Host "`nRegistration methods:" -ForegroundColor Green
    $registrations | Format-Table RecordType, UserPrincipalName, MethodType, IsDefault, IsUsable
}

Write-Host "`nUse -AsJson to emit the data for pipelines or tests." -ForegroundColor Cyan
