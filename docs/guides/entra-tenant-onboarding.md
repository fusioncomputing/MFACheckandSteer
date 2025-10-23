# Phase 3.5 — Entra Tenant Onboarding Playbook

This guide captures the operational steps required to enable MFA Check & Steer for a new Microsoft Entra (Azure AD) tenant. Use it alongside the device login helper (`scripts/connect-device-login.ps1`) and connector commands (`Get-MfaEntraSignIn`, `Get-MfaEntraRegistration`).

## 1. Prerequisites Checklist
- ✅ Tenant has Microsoft Entra P1/P2 licensing to access sign-in logs and risk data beyond seven days.
- ✅ Global Administrator (GA) account available to grant initial Graph permissions; MFA enforced on the GA account.
- ✅ Conditional Access policies permit device-code flows from the management workstation (or Exceptions documented).
- ✅ PowerShell 7.4+ installed on the operator machine running MFA Check & Steer tooling.

## 2. Required RBAC Roles
| Role | Purpose | Notes |
|------|---------|------|
| Global Administrator (temporary) | Grants admin consent for Graph scopes used by MFA Check & Steer. | Limit usage to initial setup; revert to least privilege afterward. |
| Security Reader | Read access to sign-in logs, audit logs, risk events. | Assign to the service principal or dedicated automation account. |
| Reports Reader | Access to sign-in and audit reports. | Needed for Graph `/auditLogs` endpoints. |
| Authentication Administrator (optional) | If automation will initiate MFA resets. | Not required for read-only telemetry ingestion. |

> **Recommendation:** Create a dedicated app registration (service principal) for the automation path and assign the required roles through Azure AD admin role assignments.

## 3. Admin Consent
The `Connect-MfaGraphDeviceCode` helper requests delegated scopes:
```
AuditLog.Read.All
Policy.Read.All
Directory.Read.All
UserAuthenticationMethod.Read.All
IdentityRiskyUser.Read.All
```
For automation (app-only) in later phases, the same permissions must be granted as application permissions with admin consent.

Steps:
1. GA runs `pwsh scripts/connect-device-login.ps1` and completes device login.
2. Review the console output to confirm the scopes granted and note the tenant ID.
3. If using a service principal, create an app registration and grant the equivalent application permissions via Azure Portal or `New-MgServicePrincipal`. Store the certificate/private key according to security policy (Key Vault, Windows cert store).

## 4. Conditional Access Considerations
- Ensure the workstation running MFA Check & Steer meets conditional access requirements (compliant device, location allowlist).
- If Conditional Access blocks device code auth for GA accounts, create a temporary policy exception with approval from security leadership and remove it after consent is granted.
- Document any persistent exceptions in the tenant runbook and flag for review during security audits.

## 5. Environment Validation
Run the following commands after consent is granted:
```powershell
pwsh scripts/connect-device-login.ps1              # GA or delegated admin
Import-Module ./src/MFACheckandSteer.psd1 -Force
Get-MfaEntraSignIn -StartTime (Get-Date).AddHours(-1) -EndTime (Get-Date) -Top 5 -Normalize
Get-MfaEntraRegistration -UserId 'user@tenant.onmicrosoft.com' -Normalize
```
Verify:
- No errors returned by the connector commands.
- Results include expected fields from the canonical schema.
- Throttling warnings (429s) are minimal; if observed, consider scheduling connectors during off-peak hours.

## 6. Logging & Monitoring
- Enable Azure AD diagnostic settings to export sign-in logs, audit logs, and risk detections to Log Analytics or Event Hub for long-term retention (align with compliance requirements documented in Phase 1.4).
- Create Azure Monitor alerts for failed connector runs or repeated throttling warnings once automation is operational.

## 7. Troubleshooting
| Symptom | Possible Cause | Resolution |
|---------|----------------|-----------|
| `Connect-MgGraph` fails due to policy | Conditional Access blocking device code | Update CA policy conditions or use an alternate privileged workstation. |
| `Get-MfaEntraSignIn` throws 403 | Missing Graph permission or role assignment | Ensure GA granted consent; verify Security Reader/Reports Reader assignments. |
| Frequent throttling warnings | High-volume queries during peak times | Reduce `-Top`, schedule during low traffic, or contact Microsoft support if persistent. |
| Results missing risk fields | Tenant lacks P2 license or beta profile not selected | Confirm licensing and consider installing the full `Microsoft.Graph` module to select beta profile. |

## 8. Documentation & Handover
- Record the tenant ID, app registration details, certificate thumbprints, and role assignments in the secure configuration repository (per organizational policy).
- Update `agents.md` with any tenant-specific quirks discovered during onboarding.
- Schedule the first bi-weekly stakeholder sync (Phase 1.6 cadence) with tenant-specific status.
