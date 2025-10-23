# Microsoft Entra MFA Signal Mapping (Roadmap 1.2)

This document captures the signal sources, access requirements, and retention expectations for Microsoft Entra (Azure AD) multi-factor authentication data. It provides the baseline for roadmap item **1.2 Map existing MFA signal sources** and will guide connector implementation in later phases.

## 1. Scope and Goals
- Identify every Entra MFA data surface SecOps relies on for detection, triage, and reporting.
- Describe how to connect from PowerShell with a **Global Administrator** account (or least-privilege alternatives) so we can automate ingestion.
- Record retention windows, export options, and dependencies that affect telemetry availability.
- Flag open questions SecOps must resolve before we build the Phase 3 connectors.

## 2. Access and Authentication Requirements
- **Primary account:** Global Administrator (or Privileged Role Administrator + Security Reader) is required to grant initial Graph/API consent for MFA signals. After consent, create a dedicated service principal with scoped permissions.
- **PowerShell tooling:** Use the latest `Microsoft.Graph` PowerShell modules. MFA data is exposed through `AuditLog`, `Identity.SignIns`, `Policy`, and `Reports` endpoints.
- **Required delegated Graph scopes:** `AuditLog.Read.All`, `Policy.Read.All`, `Directory.Read.All`, `UserAuthenticationMethod.Read.All`, `IdentityRiskyUser.Read.All`. For app-only access, configure equivalent application permissions and approve admin consent.
- **Authentication flow:** Enforce certificate-based auth for automation service principals. Human analysts should use interactive `Connect-MgGraph` with MFA enforced.

```powershell
# Analyst interactive session
Install-Module Microsoft.Graph -Scope CurrentUser
Connect-MgGraph -Scopes "AuditLog.Read.All","Policy.Read.All","Directory.Read.All","UserAuthenticationMethod.Read.All"
Select-MgProfile -Name beta  # sign-in log risk detail currently requires beta profile
```

## 3. Entra MFA Signal Surfaces

| Surface | Description | Access Path | Key Fields |
|---------|-------------|-------------|------------|
| Sign-in logs | Authentication attempts (interactive & non-interactive) with MFA requirement and result. | `Get-MgAuditLogSignIn` / Graph `/auditLogs/signIns` | `userDisplayName`, `userPrincipalName`, `ipAddress`, `mfaDetail`, `conditionalAccessStatus`, `riskDetail`, `correlationId` |
| Authentication method registration details | MFA registration status per user. | `Get-MgUserAuthenticationMethod` / `/users/{id}/authentication/methods` | `methodType`, `isDefault`, `createdDateTime`, `lastUpdatedDateTime` |
| MFA service settings and policies | Tenant-wide MFA configuration, enforcement, fraud alert settings. | `Get-MgPolicyAuthenticationMethodPolicy` / `/policies/authenticationMethodsPolicy` | `policyVersion`, `registrationEnforcement`, `methodConfigurations` |
| Conditional Access policies | Policies dictating when MFA is required/bypassed. | `Get-MgIdentityConditionalAccessPolicy` / `/identity/conditionalAccess/policies` | `conditions`, `grantControls`, `sessionControls`, `state` |
| Identity Protection risk events | Risky user/sign-in signals leveraged by adaptive MFA. | `Get-MgIdentityRiskyUser` / `/identityProtection/riskyUsers`; `Get-MgIdentityRiskySignIn` | `riskLevel`, `riskState`, `riskDetections` |
| Audit logs | Administrative changes to MFA settings. | `Get-MgAuditLogDirectoryAudit` / `/auditLogs/directoryAudits` | `targetResources`, `activityDisplayName`, `initiatedBy`, `result` |
| Diagnostic settings | Export pipeline to Log Analytics, Event Hub, or Storage for long-term retention. | Azure Portal / Resource Manager | Export frequency, destination, retention days |

## 4. Data Retention and Export
- **Portal / API defaults:** Sign-in logs are available for 7 days on free tenants and 30 days for P1/P2. Audit logs retain 30 days. Risk detections retain 90 days by default.
- **Extended retention:** Configure Diagnostic Settings to stream sign-in logs, audit logs, and risk events to Log Analytics (up to 730 days), Azure Storage (configurable), or Event Hub.
- **Offline samples:** For development, capture sanitized JSON exports via `Get-MgAuditLogSignIn -Top 500 | ConvertTo-Json` and store under a non-production path with no personal data.
- **Gaps to close:** Confirm whether SecOps already exports MFA data to a SIEM. If so, capture schema and retention policies to avoid double ingestion.

## 5. Connection Workflow Summary
1. Global Administrator grants consent for Graph permissions using `Connect-MgGraph -Scopes ...` or via Azure Portal app registration.
2. Create a dedicated Azure AD app registration with certificate credentials; assign application permissions matching the scopes above and approve admin consent.
3. Store the certificate private key in a secure location (Azure Key Vault, Windows Certificate Store) accessible to the automation host.
4. Implement PowerShell connection helper, e.g.:
   ```powershell
   function Connect-EntraMfaTenant {
       param (
           [Parameter(Mandatory)] [string] $TenantId,
           [Parameter(Mandatory)] [string] $ClientId,
           [Parameter(Mandatory)] [string] $CertThumbprint
       )
       Connect-MgGraph -TenantId $TenantId -ClientId $ClientId -CertificateThumbprint $CertThumbprint -NoWelcome
       Select-MgProfile -Name beta
   }
   ```
5. Validate access by running smoke tests (`Get-MgAuditLogSignIn -Top 1`, `Get-MgUserAuthenticationMethod -UserId <id>`). Capture sample payload structure for schema normalization.
6. Document the tenant IDs, app registrations, and contacts responsible for credential rotation.

## 6. Security and Compliance Considerations
- Enforce least privilege by moving Global Administrator usage to initial setup only; daily operations should use `Security Reader`, `Reports Reader`, or custom roles with equivalent read permissions.
- Monitor app registration sign-ins; enable conditional access requiring compliant devices for administrative runbooks.
- Record data classification: sign-in logs contain PII (user IDs, IPs). Ensure storage targets meet the organization's regulatory obligations and that exports are encrypted at rest.
- Align diagnostic exports with existing retention policies to prevent redundant storage and ensure legal hold requirements are satisfied.

## 7. Open Questions / Next Actions
- Confirm whether SecOps wants additional telemetry (e.g., Azure AD B2C, GovCloud tenants) within scope for this phase.
- Identify the preferred export target (Log Analytics workspace vs. Event Hub) for long-term retention before implementing ingestion pipelines in Phase 3.
- Decide on schema versioning strategy so future provider connectors align with Entra's canonical model.
- Schedule credential provisioning for the service principal, including certificate issuance and rotation policy.
