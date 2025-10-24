# Detection Spec - MFA-DET-004 Repeated MFA Failures

| Field | Value |
|-------|-------|
| ID | MFA-DET-004 |
| Name | Repeated MFA Failures |
| Severity | Medium |
| Owner | SecOps Detection Engineering |
| Last Review | 2025-10-24 |

## Description
Surface users experiencing a burst of multi-factor authentication failures within a short window. These spikes often indicate password spraying, push fatigue campaigns, or automated attacks probing factor resilience. Early detection helps SecOps reset credentials, block offending IPs, and validate user intent before an adversary escalates access.

## Data Requirements
- Canonical sign-in dataset from `Get-MfaEntraSignIn -Normalize`.
- Optional: Identity Protection risk signals to correlate with risk states (informational but not required for triggering).
- Optional: SIEM enrichment (IP reputation, geo metadata) for playbook triage.

## Logic (Pseudocode)
```
param(
    [int] $FailureThreshold = 3,
    [int] $FailureWindowMinutes = 15,
    [int] $ObservationHours = 24,
    [psobject[]] $SignIns
)

$windowStart = $ReferenceTime.AddHours(-$ObservationHours)
$failures = $SignIns |
    Where-Object { $_.Result -eq 'Failure' -and $_.CreatedDateTime -ge $windowStart } |
    Group-Object UserPrincipalName

foreach ($group in $failures) {
    $queue = New-Object System.Collections.Generic.Queue[datetime]
    foreach ($record in ($group.Group | Sort-Object CreatedDateTime)) {
        while ($queue.Count -gt 0 -and ($record.CreatedDateTime - $queue.Peek()).TotalMinutes -gt $FailureWindowMinutes) {
            $null = $queue.Dequeue()
        }
        $queue.Enqueue($record.CreatedDateTime)
        if ($queue.Count -ge $FailureThreshold) {
            Emit detection (Severity = Medium, include reasons/error codes)
            break
        }
    }
}
```

## Tunable Parameters
- `FailureThreshold` — Minimum number of failures inside the sliding window (default 3; recommended range 3–6).
- `FailureWindowMinutes` — Size of the sliding window in minutes (default 15; recommended range 5–60).
- `ObservationHours` — Backward-looking window for sourcing sign-ins (default 24 hours).

## Considerations
- Service desk resets or conditional access testing can cause benign bursts; pair with source IP/device context during triage.
- Combine with Identity Protection risk states or suspicious IP reputation to prioritize critical cases.
- Coordinate with conditional access to avoid duplicate alert channels for the same spray activity.

## Framework Alignment
- **MITRE ATT&CK**: `T1110` (Brute Force), `T1621` (Multi-Factor Authentication Interception)
- **NIST CSF**: `DE.AE-2`, `DE.CM-7`

## Reporting Tags
- `Authentication`
- `RepeatedFailure`
- `Risk-Medium`

## Response Mapping
- Leverage `MFA-PL-002` (Contain High-Risk Sign-In) until a dedicated containment playbook (`MFA-PL-005`) is finalized. Focus on credential resets, temporary blocks, and monitoring follow-on attempts.

## Testing
- Scenario `INC-005` (`data/scenarios/INC-005.json`) exercises the positive path with three MFA denials inside 10 minutes.
- Unit tests mock sliding-window behaviour to ensure the first qualifying burst emits a detection and subsequent noise does not regress results.
- Negative test: failures spread across hours should not trigger when outside the sliding window.
