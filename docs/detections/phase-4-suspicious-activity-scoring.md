# Phase 4.2 - Suspicious Activity Scoring

Roadmap item **4.2** introduces a lightweight scoring model that helps SecOps teams prioritize investigative effort on risky MFA activity. The score correlates multiple weak signals into an aggregate view per user/session, enabling analysts to spot MFA fatigue, credential reuse, and emergency factor changes that might otherwise slip through single-rule detections.

## Objectives
- Combine diverse telemetry (sign-in events, registration changes) into a simple, explainable score.
- Highlight scenarios where multiple medium-risk signals compound into a high-severity situation.
- Provide structured output that downstream automation (reporting, ticketing, playbooks) can consume without additional parsing.
- Remain PowerShell-first and executable in environments with limited third-party tooling.

## Signals & Weights
The initial model assigns additive weights to the following indicators. Values are tunable and will evolve with SecOps feedback.

| Indicator | Default Weight | Detection Criteria |
|-----------|----------------|--------------------|
| `ImpossibleTravel` | 40 | Same user signs in from different countries within `TravelWindowMinutes` (default 120 minutes). |
| `RepeatedFailures` | 20 | `FailureThreshold` (default 3) or more failed MFA attempts for a user within `FailureWindowMinutes` (default 30 minutes). |
| `UnusualDevice` | 15 | Sign-in contains `RiskDetail` in `('unfamiliarFeaturesOfThisDevice','newDevice','registerSecurityInformation')` or failure details referencing unfamiliar devices. |
| `HighRiskFactorChange` | 25 | Default MFA method changed within `RecentRegistrationDays` (default 7 days) to a weaker factor (SMS/phone/temporary password). |

Additional metadata (e.g., Identity Protection risk levels, device IDs) can be layered on later as Phase 3 connectors mature.

## Severity Bands
- **0-24** -> `Informational`
- **25-49** -> `Medium`
- **50-74** -> `High`
- **75+** -> `Critical`

These ranges are intentionally conservative; SecOps can tune them via parameters once more empirical data is available.

## Output Schema
`Invoke-MfaSuspiciousActivityScore` (implemented in the PowerShell module) emits one record per user with the following shape:

| Field | Description |
|-------|-------------|
| `UserPrincipalName` | User the score applies to. |
| `Score` | Total points from all triggered indicators. |
| `Severity` | Derived from the severity bands above. |
| `Indicators` | Array of indicator objects (`Type`, `Weight`, `Details`, `Timestamp`). |
| `WindowStart` / `WindowEnd` | Observation window used for sign-in analysis. |
| `SignInCount` | Number of sign-in records evaluated for the user. |
| `FailureCount` | Failed sign-ins within the window (for quick triage context). |
| `SignalId` | Constant `MFA-SCORE` identifier for downstream routing. |
| `FrameworkTags` | MITRE ATT&CK identifiers associated with the correlated indicators. |
| `NistFunctions` | Applicable NIST CSF categories (mapped in Phase 4.3). |
| `ReportingTags` | Standardized reporting tags, including `Risk-{Severity}` tokens for dashboards. |

## Operational Flow
1. Collect sign-in telemetry via `Get-MfaEntraSignIn -Normalize` for the observation window (default 24 hours).
2. Optionally gather canonical registration data via `Get-MfaEntraRegistration -Normalize` for users under review.
3. Run `Invoke-MfaSuspiciousActivityScore [-SignInData ...] [-RegistrationData ...]` to generate scores.
4. Sort by `Score` or filter on `Severity` to drive analyst queues, dashboards, or automated notifications.
5. Link resulting indicators to Phase 5 response playbooks (e.g., forced reset, targeted outreach).

## Sample Dataset Coverage
`data/samples/entra-signins-sample.json` and `data/samples/entra-registrations-sample.json` now include:
- Back-to-back country changes for `analyst@example.com` to demonstrate impossible travel.
- Multiple failures for `engineer@example.com` to trigger repeated failure detection.
- Device risk detail examples (`unfamiliarFeaturesOfThisDevice`) to represent unusual device fingerprints.
- A recent fallback to SMS for `security.admin@example.com` to flag high-risk factor change.

These samples back the unit tests under `tests/MFACheckandSteer.Tests.ps1` and can be replayed via `scripts/replay-samples.ps1` for demos.

## Next Steps
1. Correlate the scoring output with detection rules (e.g., automatically escalate `High`/`Critical` scores to ticketing in Phase 5).
2. Extend indicator coverage to include Identity Protection risk events once those connectors are finalized.
3. Feed scores into reporting exports (Phase 6) and trend analysis to monitor improvements in SecOps posture.
4. Gather production telemetry to recalibrate weights and thresholds, reducing false positives over time.

