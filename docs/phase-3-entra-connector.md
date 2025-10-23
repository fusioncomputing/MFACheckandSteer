# Phase 3 — Microsoft Entra MFA Connector (Provider Slice v1)

This document records the implementation details for roadmap tasks **3.1–3.6** scoped to the initial Microsoft Entra MFA connector. The goal is to provide a thin, production-ready PowerShell interface that SecOps can call once Graph access is configured, while remaining simple enough for iterative enhancement.

## Objectives
- Expose PowerShell functions to retrieve sign-in activity and MFA registration methods from Microsoft Graph.
- Encapsulate filter building logic so analysts can request time-bounded data without memorizing OData syntax.
- Support future automation by keeping function parameters script-friendly and testable with mocks.
- Offer built-in canonical normalization while allowing raw payload access when needed.

## Functions Added
| Function | Purpose | Notes |
|----------|---------|-------|
| `Get-MfaEntraSignIn` | Fetch sign-in logs with optional user filter and custom date range. | Requires prior `Connect-MgGraph`; supports `-Normalize` for canonical output and `-MaxRetries` (default 3) to automatically retry throttled calls. |
| `Get-MfaEntraRegistration` | Retrieve authentication methods for one or more users. | Wraps `Get-MgUserAuthenticationMethod`; supports `-Normalize` for canonical output and `-MaxRetries` for throttling resilience. |
| `Connect-MfaGraphDeviceCode` | Convenience helper that runs Microsoft Graph device login using a Global Admin account. | Selects the beta profile by default after authentication and returns the resulting context. |
| `ConvertTo-MfaCanonicalSignIn` / `ConvertTo-MfaCanonicalRegistration` | Convert raw Microsoft Graph objects into the canonical schema. | Used internally by `-Normalize`; exposed for advanced pipelines. |

Both functions validate Graph availability via `Get-MgContext` and throw actionable errors when prerequisites are missing.

## Usage Examples
```powershell
# Connect using service principal or interactive auth before calling.
Connect-MgGraph -TenantId $TenantId -ClientId $ClientId -CertificateThumbprint $Thumbprint
Select-MgProfile -Name beta

# Or perform a one-time device login with a Global Admin and cached credentials.
# The helper re-runs scripts/setup.ps1 to install/upgrade the Microsoft.Graph bundle if needed:
.\scripts\connect-device-login.ps1

# Pull the last 24 hours of sign-ins for a specific user and normalize
Get-MfaEntraSignIn -StartTime (Get-Date).AddHours(-24) -EndTime (Get-Date) -UserPrincipalName 'analyst@contoso.com' -Normalize

# Export current authentication methods for a user list
$users = @('user1@contoso.com', 'user2@contoso.com')
$users | ForEach-Object { Get-MfaEntraRegistration -UserPrincipalName $_ -Normalize }
```

## Testing Strategy
- Unit tests mock `Get-MgAuditLogSignIn` and `Get-MgUserAuthenticationMethod` to verify parameter translation and guard clauses.
- No live Graph calls are executed in CI; smoke tests still ensure module import succeeds.

## Release Planning (Provider vNext)
- **Provider v1 (current)** — Interactive/device code auth with GA onboarding, sign-in & registration retrieval, canonical normalization, retry resilience, sample datasets.
- **Provider v1 Acceptance Tests**:
  - Unit tests validating filter construction, throttling retries, normalization outputs.
  - Replay script runs (`scripts/replay-samples.ps1 -Dataset All -AsJson`) without error.
  - Manual smoke: `Get-MfaEntraSignIn` and `Get-MfaEntraRegistration` return data in a sandbox tenant.
- **Provider v2 Goals** (future roadmap):
  - Add pagination helpers / chunked processing for large time windows.
  - Introduce configurable tenant/user filters and exclude lists (e.g., `config/tenant-filters.json`).
  - Emit structured telemetry (duration, record counts) for health dashboards.
  - Publish acceptance test suite that mocks pagination and verifies filter configuration.
- **Release Checklist Template** (store in `docs/guides`):
  1. Update `Docs` (`phase-3-...` files) with new features or configuration options.
  2. Add/adjust sample datasets to cover new scenarios.
  3. Ensure Pester tests cover happy path and failure scenarios; run `Invoke-Pester -CI`.
  4. Bump module version in `src/MFACheckandSteer.psd1` when breaking/backward-compatible feature toggles are introduced.
  5. Draft release notes summarizing improvements, risk considerations, and required ops actions.

## Follow-Up Enhancements
- Extend canonical schema coverage (e.g., full location metadata, risk detections) as additional connectors are added.
- Add pagination helpers or chunked processing for large query windows.
- Introduce tenant/user filters driven by configuration files once ingestion pipelines are formalized.
- Capture telemetry (duration, record counts) for use in future health dashboards.

## Resilience Features
- Both connector cmdlets route their Microsoft Graph calls through `Invoke-MfaGraphWithRetry`, which performs exponential backoff (1s, 2s, 4s, ...) up to the specified `-MaxRetries` when a 429/throttling response is detected.
- Retry logic inspects status codes and exception messages so it works with the Graph PowerShell SDK and direct Graph requests alike.
- Warnings are emitted when a retry occurs, giving operators visibility into throttling events without interrupting automation.
