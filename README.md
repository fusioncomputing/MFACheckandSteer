# MFA Check & Steer

This repository will host MFA Check & Steer, a project focused on tooling and guidance around multi-factor authentication validation and remediation workflows. The project is just getting started; see `agents.md` for the Codex agent's operating notes on the Windows environment.

## Getting Started
- Ensure you have PowerShell 7.4+ available; all examples assume PowerShell unless otherwise specified.
- Clone this repository: `git clone https://github.com/fusioncomputing/MFACheckandSteer.git`.
- Run `scripts/setup.ps1` to install required modules (Pester, PSScriptAnalyzer, Microsoft.Graph).
- Execute `scripts/smoke-tests.ps1` to validate your environment, then `Invoke-Pester -Path tests` to run the baseline test suite.
- Review `roadmap.md` for the current development plan and `agents.md` for implementation guidance tailored to Windows.

Continuous integration runs the same setup and Pester tests on Windows runners via GitHub Actions.
