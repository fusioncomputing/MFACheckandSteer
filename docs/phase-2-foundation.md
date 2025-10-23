# Phase 2 — Foundation & Tooling Decisions

This document records the deliverables for roadmap items **2.1–2.6** with a bias toward simple, PowerShell-first tooling as requested.

## 2.1 Technology Stack
- Primary runtime: PowerShell 7.4+ (cross-platform support retained, but Windows remains primary).
- Module structure: single PowerShell module `MFACheckandSteer` under `src/` with manifest for versioning.
- Optional .NET components are deferred; rely on Microsoft Graph PowerShell modules for Entra access.
- Testing: Pester 5.5+.
- Static analysis: PSScriptAnalyzer (baseline rules).

## 2.2 Repository Automation
- `.gitattributes` enforces CRLF for PowerShell assets to avoid diff noise on Windows contributors.
- GitHub Actions workflow (`powershell-ci.yml`) runs setup script then Pester tests on Windows runners.
- No additional task runners introduced to keep workflow lightweight.

## 2.3 Developer Bootstrap
- `scripts/setup.ps1` installs required PowerShell modules (Pester, PSScriptAnalyzer, Microsoft.Graph) into the current user scope and confirms versions.
- Script intentionally avoids complex logging or dependency managers to stay minimal.

## 2.4 Continuous Integration
- GitHub Actions workflow uses `actions/setup-pwsh` with PowerShell 7.4.
- Steps: checkout → run `scripts/setup.ps1` → execute `Invoke-Pester` with default configuration.
- Future expansion (security scanning, packaging) will be added when functionality grows.

## 2.5 Secret Handling Pattern
- Service principal certificate-based auth remains the preferred automation mechanism (see `docs/entra-mfa-signal-map.md`). No secrets are stored in repo.
- Local development instructions emphasize using Windows Credential Manager or Azure Key Vault; details will live in forthcoming runbook once connectors exist.
- For now, module exposes placeholder `Get-MfaEnvironmentStatus` to verify access without storing credentials.

## 2.6 Environment Validation
- `scripts/smoke-tests.ps1` imports the module and checks Graph connectivity prerequisites (module availability, profile selection).
- Dependency matrix (PowerShell 7.4, modules listed above) documented within `scripts/setup.ps1` output; additional machine-readable format can be added later if needed.

## Follow-Up Actions
- Flesh out module functions during Phase 3 when ingestion logic is implemented.
- Expand smoke tests to call real Graph endpoints once service principal credentials are provisioned.
- Revisit CI to add linting gate (PSScriptAnalyzer) after initial functions stabilize.
