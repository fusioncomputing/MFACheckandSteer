# Detection Spec - MFA-DET-005 Impossible Travel + MFA Success

| Field | Value |
|-------|-------|
| ID | MFA-DET-005 |
| Name | Impossible Travel + MFA Success |
| Severity | High |
| Owner | SecOps Detection Engineering |
| Last Review | 2025-10-24 |

## Description
Detect successful MFA sign-ins that occur from geographically distant locations within an implausibly short timeframe. Such events often indicate token theft, session hijacking, or MFA fatigue attacks where an adversary reuses a newly granted session from another region. Prompt investigation helps SecOps revoke compromised sessions and validate user activity before additional abuse occurs.

## Data Requirements
- Canonical sign-in dataset from `Get-MfaEntraSignIn -Normalize` including location metadata.
- Optional: Conditional access context (`AuthenticationRequirement`, `AuthenticationMethods`) to confirm MFA enforcement.
- Optional: Geo-IP enrichment for finer distance calculations (future enhancement).

## Logic (Pseudocode)
```
param(
    [int] $TravelWindowMinutes = 120,
    [bool] $RequireMfaRequirement = $true,
    [bool] $RequireSuccess = $true,
    [psobject[]] $SignIns
)

$windowStart = $ReferenceTime.AddHours(-$ObservationHours)
$users = $SignIns | Group-Object UserPrincipalName

foreach ($user in $users) {
    $records = $user.Group | Sort-Object CreatedDateTime
    for ($i = 1; $i -lt $records.Count; $i++) {
        $current = $records[$i]
        if ($RequireSuccess -and $current.Result -ne 'Success') { continue }
        if ($RequireMfaRequirement -and ($current.AuthenticationRequirement -notmatch 'mfa')) { continue }

        for ($j = $i - 1; $j -ge 0; $j--) {
            $previous = $records[$j]
            $delta = $current.CreatedDateTime - $previous.CreatedDateTime
            if ($delta.TotalMinutes -gt $TravelWindowMinutes) { break }
            if ($previous.Country -ne $current.Country) {
                Emit detection (Severity = High, include countries/IPs/timestamps)
                break
            }
        }
    }
}
```

## Tunable Parameters
- `ObservationHours` — Backward-looking window for sourcing sign-ins (default 24 hours, inherits from detection configuration).
- `TravelWindowMinutes` — Maximum allowable minutes between sign-ins before treating travel as impossible (default 120; recommended range 30–240).
- `RequireMfaRequirement` — Ensure the later sign-in was subject to MFA (default `true`).
- `RequireSuccess` — Restrict to successful sign-ins (default `true`; disable to hunt near-miss events).

## Considerations
- Geo-IP resolution can be coarse; false positives may arise for neighboring countries (e.g., EU border crossings). Pair with IP ranges and device identifiers during triage.
- VPN gateways and security appliances may intentionally route traffic through distant points—maintain exclusion lists for trusted infrastructure.
- Future enhancement: compute actual distance using latitude/longitude for precision.

## Framework Alignment
- **MITRE ATT&CK**: `T1078` (Valid Accounts), `T1110` (Credential Access)
- **NIST CSF**: `DE.AE-2`, `DE.CM-7`

## Reporting Tags
- `Authentication`
- `ImpossibleTravel`
- `Risk-High`

## Response Mapping
- Planned playbook `MFA-PL-006` will drive token revocation, conditional access review, and user validation steps. In the interim, leverage `MFA-PL-002` to reset credentials and revoke sessions when high-risk sign-ins overlap.

## Testing
- Scenario `INC-006` (`data/scenarios/INC-006.json`) captures an impossible travel success between Canada and Germany within 20 minutes.
- Unit tests cover parameter overrides (e.g., relaxing `RequireSuccess`) to ensure configurability.
- Negative test: legitimate travel outside the configured window should not trigger.
