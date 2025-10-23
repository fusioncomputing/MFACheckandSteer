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
- `scripts/` - Setup, smoke-test, sample replay, and device login helper scripts (device login reruns the setup script to ensure dependencies are present).
- `tests/` - Pester tests executed locally and in CI.
- `data/samples/` - Synthetic canonical datasets for sign-ins and registrations, used by `scripts/replay-samples.ps1`.
- `docs/guides/` - Operational playbooks (e.g., Entra tenant onboarding checklist).
- `docs/detections/` - Detection strategy, rule specs, and future playbooks/tests (Phase 4).
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

## Sample Data
- Run `pwsh scripts/replay-samples.ps1` to view the synthetic MFA datasets included under `data/samples/`.
- Use `-Dataset SignIn|Registration` and `-AsJson` to export specific samples for automated tests or demos.
- Refer to `docs/phase-3-sample-data.md` for detailed guidance.

## Next Steps
- Implement Entra MFA data connectors and schema normalization (roadmap Phase 3).
- Expand detection rules, response playbooks, and reporting once telemetry is flowing.
- Tighten CI gates with linting and packaging when functional modules are in place.
