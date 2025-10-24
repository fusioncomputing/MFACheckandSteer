# MFA Check & Steer

MFA Check & Steer delivers PowerShell-first tooling that helps SecOps teams detect, triage, and remediate risky MFA activity. Phase 1 discovery and governance documents are complete, and Phase 2 has established the base PowerShell module, test harness, and CI pipeline. See `agents.md` for the Codex agent's operating notes on the Windows environment.

## Getting Started
- Ensure you have PowerShell 7.4+ available; all examples assume PowerShell unless otherwise specified.
- Clone this repository: `git clone https://github.com/fusioncomputing/MFACheckandSteer.git`.
- Run `scripts/setup.ps1` to install required modules (Pester, PSScriptAnalyzer, Microsoft.Graph).
- Execute `scripts/smoke-tests.ps1` to validate your environment, then `Invoke-Pester -Path tests` to run the baseline test suite.
- When a Global Administrator is available, run `scripts/connect-device-login.ps1` to complete a device-code Microsoft Graph sign-in and cache credentials for subsequent commands.
- Review `roadmap.md` for the numbered development plan and `agents.md` for implementation guidance tailored to Windows.
- Explore the Phase 1 deliverables in `docs/` (stakeholder interviews, KPI baseline, compliance notes, project charter, cadence plan).
- Inspect the PowerShell module under `src/` and accompanying tests in `tests/` to understand current capabilities.

Continuous integration runs the same setup and Pester tests on Windows runners via GitHub Actions.

## Repository Layout
- `docs/` - Phase 1 discovery artifacts and Phase 2 foundation decisions.
- `src/` - `MFACheckandSteer` PowerShell module (baseline environment checks).
- `scripts/` - Setup, smoke-test, scenario/sample replay, and device login helper scripts (device login reruns the setup script to ensure dependencies are present).
- `tests/` - Pester tests executed locally and in CI.
- `data/samples/` - Synthetic canonical datasets for sign-ins and registrations, used by `scripts/replay-samples.ps1`.
- `data/scenarios/` - Incident-focused telemetry bundles exercised by `scripts/replay-scenarios.ps1` and Pester scenario tests.
- `config/` - Detection configuration (`detections.json`) that applies Phase 4.5 overrides for thresholds and risk tuning.
- `docs/guides/` - Operational playbooks (e.g., Entra tenant onboarding checklist).
- `docs/detections/` - Detection strategy, rule specs, framework/tag mappings, and future playbooks/tests (Phase 4).
- `.github/workflows/` - Windows CI pipeline (`powershell-ci.yml`).

## Current PowerShell Commands
- `Get-MfaEnvironmentStatus` - Report availability and versions of required PowerShell modules.
- `Test-MfaGraphPrerequisite` - Quick check to confirm Microsoft Graph tooling is installed.
- `Connect-MfaGraphDeviceCode` - Guide a Global Admin through device login and return the active Graph context (device helper reruns the setup script first).
- `Get-MfaEntraSignIn` - Retrieve Microsoft Entra sign-in logs for a given time window (supports `-Normalize` for canonical output and `-MaxRetries` for throttling resilience).
- `Get-MfaEntraRegistration` - Fetch MFA authentication methods for specified users (supports `-Normalize` and `-MaxRetries`).
- `ConvertTo-MfaCanonicalSignIn` / `ConvertTo-MfaCanonicalRegistration` - Transform raw Graph objects into the schema described in `docs/phase-3-canonical-schema.md`.
- `Invoke-MfaDetectionDormantMethod` - Flag default MFA methods that have not been updated recently.
- `Invoke-MfaDetectionHighRiskSignin` - Surface successful sign-ins that carry Identity Protection risk signals.
- `Invoke-MfaDetectionRepeatedMfaFailure` - Detect bursts of MFA failures within a tunable window.
- `Invoke-MfaDetectionImpossibleTravelSuccess` - Flag rapid geography changes that still succeed with MFA.
- `Invoke-MfaDetectionPrivilegedRoleNoMfa` - Identify privileged identities lacking compliant MFA coverage.
- `Invoke-MfaSuspiciousActivityScore` - Correlate impossible travel, repeated failures, unusual devices, and recent factor changes into a per-user priority score.
- `Get-MfaDetectionConfiguration` - Inspect the merged detection configuration (defaults plus overrides) used by Phase 4.5 tuning.
- `Invoke-MfaPlaybookResetDormantMethod` - Apply playbook `MFA-PL-001` to revoke stale factors identified by `MFA-DET-001` with guardrails and audit-friendly output.
- `Invoke-MfaPlaybookEnforcePrivilegedRoleMfa` - Apply playbook `MFA-PL-003` to restore compliant MFA coverage for privileged identities.
- `Invoke-MfaPlaybookContainHighRiskSignin` - Apply playbook `MFA-PL-002` to contain successful risky sign-ins identified by `MFA-DET-002`.
- `Invoke-MfaPlaybookContainRepeatedFailure` - Apply playbook `MFA-PL-005` to contain MFA failure storms uncovered by `MFA-DET-004`.
- `Invoke-MfaPlaybookInvestigateImpossibleTravel` - Apply playbook `MFA-PL-006` when `MFA-DET-005` flags suspicious impossible travel successes.
- `Invoke-MfaPlaybookTriageSuspiciousScore` - Apply playbook `MFA-PL-004` to triage aggregated suspicious activity scores.
- All detection and scoring outputs include `FrameworkTags`, `NistFunctions`, and `ReportingTags` to satisfy Phase 4.3 governance requirements (see `docs/detections/phase-4-framework-mapping.md`).

## Sample Data
- Run `pwsh scripts/replay-samples.ps1` to view the synthetic MFA datasets included under `data/samples/`.
- Use `pwsh scripts/replay-scenarios.ps1 -List` to view curated incident scenarios, then run a scenario (e.g., `-ScenarioId INC-001`) to exercise detections end-to-end.
- Add `-SimulatePlaybooks` when replaying scenarios to execute playbooks in `-WhatIf` mode and preview the remediation checklist associated with each signal.
- Use `-Dataset SignIn|Registration` and `-AsJson` to export specific samples for automated tests or demos.
- Refer to `docs/phase-3-sample-data.md` for detailed guidance.

## Configuration
- Edit `config/detections.json` to tune detection thresholds (e.g., `DormantDays`, suspicious activity scoring windows) following the guidance in `docs/detections/phase-4-configuration.md`.
- Run `Get-MfaDetectionConfiguration` (optionally with `-Refresh`) to confirm effective settings; overrides apply automatically unless cmdlet parameters are provided at call time.
- Set the `MfaDetectionConfigurationPath` environment variable to point at an alternate JSON file when testing changes or running scenario-specific baselines.

- Review `docs/detections/playbooks/phase-5-response-strategy.md` for the Phase 5 remediation playbook approach and the individual playbook specs under `docs/detections/playbooks/` (MFA-PL-001 through MFA-PL-006).

## Next Steps
- Integrate the new detection outputs (MFA-DET-004 and MFA-DET-005) into dashboards, alerting, and analyst workflows.
- Integrate playbook outputs (MFA-PL-001 through MFA-PL-006) with ticketing/notification workflows.
- Feed suspicious activity scores into dashboards and ticketing workflows (Phase 5 and 6).
- Tighten CI gates with linting and packaging when functional modules are in place.
