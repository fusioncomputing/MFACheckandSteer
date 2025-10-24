# Phase 4.4 - Synthetic Incident Scenarios & Test Harness

Roadmap task **4.4** expands detection validation beyond unit tests by introducing curated incident scenarios that exercise canonical data pipelines, detections, and scoring outputs end-to-end.

## Objectives
- Provide SecOps-aligned narratives (attacker + defender perspectives) that demonstrate how MFA Check & Steer detections light up during common incidents.
- Deliver reusable PowerShell harnesses that load synthetic telemetry, execute detections, and surface expected findings.
- Support CI automation and analyst tabletop reviews using the same scenario assets.

## Initial Scenario Catalog

| Scenario ID | Name | Summary | Primary Coverage | Expected Signals |
|-------------|------|---------|------------------|------------------|
| `INC-001` | MFA Fatigue Spray | Adversary performs password spray followed by repeated MFA push attempts against a privileged engineer. | `MFA-DET-002`, Suspicious score (`RepeatedFailures`, `UnusualDevice`) | High-risk success (if fatigue succeeds), medium/high aggregated score. |
| `INC-002` | Dormant Factor Abuse | Stolen legacy phone factor abused after long dormancy; user signs in from new geography. | `MFA-DET-001`, Suspicious score (`ImpossibleTravel`) | Dormant method detection, medium aggregated score. |
| `INC-003` | Emergency Factor Downgrade | Privileged admin resets MFA to SMS after phishing, then high-risk sign-in occurs. | `MFA-DET-002`, Suspicious score (`HighRiskFactorChange`) | High severity score, high-risk detection. |
| `INC-004` | Privileged Admin Without MFA | Privileged account lacks any registered MFA method, prompting enforcement playbook. | `MFA-DET-003` | Critical detection for privileged role without MFA. |

> Additional scenarios (e.g., service accounts, token theft) can be layered on as new detections ship.

## Artifacts
1. **Synthetic datasets** – JSON fixtures stored in `data/scenarios/` (sign-ins + registrations per scenario).
2. **Replay script** – `scripts/replay-scenarios.ps1` loads scenario data, runs detections/scoring, and prints summarized findings.
3. **Pester tests** – New block in `tests/MFACheckandSteer.Tests.ps1` to run each scenario and assert expected detections/scores.

## Execution Flow
```powershell
pwsh scripts/replay-scenarios.ps1 -ScenarioId INC-001 -Verbose
```
1. Script loads scenario fixture (sign-ins, registrations, role assignments when provided).
2. Executes detection cmdlets (`Invoke-MfaDetectionDormantMethod`, `Invoke-MfaDetectionHighRiskSignin`, `Invoke-MfaDetectionPrivilegedRoleNoMfa`) and score helper using in-memory data only.
3. Outputs findings, including framework/reporting tags.

## Testing Goals
- Ensure detections are resilient to real-world-like data variations (timestamps, missing fields, mixed severities).
- Provide guardrails so future schema or logic changes are validated against known incidents.
- Enable SecOps to rehearse response playbooks (Phase 5) with deterministic data.

## Next Steps
1. Populate the `data/scenarios/` fixtures and build the replay script.
2. Add Pester coverage and integrate scenarios into CI pipeline.
3. Expand scenario catalog when new detections or providers are added.
