# Detection Spec — MFA-DET-002 High-Risk Sign-In Approved

| Field | Value |
|-------|-------|
| ID | MFA-DET-002 |
| Name | High-Risk Sign-In Approved |
| Severity | High |
| Owner | SecOps Detection Engineering |
| Last Review | 2025-10-23 |

## Description
Trigger when Microsoft Entra Identity Protection classifies a sign-in as at risk (`RiskState` = `atRisk` or `RiskDetail` indicates elevated threat) but the authentication ultimately succeeds (`Result` = `Success`). This can indicate MFA fatigue or compromised factors.

## Data Requirements
- Canonical sign-in dataset produced by `Get-MfaEntraSignIn -Normalize`.
- Optional enrichment: user risk level from Identity Protection (future schema extension).

## Logic (Pseudocode)
```
$cutoffMinutes = 60  # Optional sliding window grouping

Get-MfaEntraSignIn -Normalize -StartTime (Get-Date).AddHours(-24) -EndTime (Get-Date)
    | Where-Object {
        $_.Result -eq 'Success' -and
        ($_.RiskState -eq 'atRisk' -or $_.RiskDetail -notin @('none', $null, 'unknownFutureValue'))
    }
    | Select CreatedDateTime, UserPrincipalName, RiskDetail, RiskLevelAggregated, AuthenticationMethods
```

## Tunable Parameters
- `ObservationWindow` — how far back to query sign-ins (default 24 hours).
- `RiskCriteria` — allow filtering to specific risk details (e.g., `passwordSpray`, `travelAtRisk`).

## Considerations
- Ensure beta profile is selected when retrieving sign-ins so risk details are populated.
- Coordinate with SOC on expected false positives (e.g., known geolocation anomalies).

## Response Mapping
- Immediate user outreach to confirm sign-in legitimacy.
- Enforce step-up (password reset / factor rotation) if suspicious.
- Log incident in ticketing system with correlation ID for deeper investigation.

## Testing
- Extend sample sign-in dataset with a high-risk success entry and confirm detection identifies it.
