# Playbook MFA-PL-001 – Reset Dormant MFA Method

| Field | Value |
|-------|-------|
| Playbook ID | MFA-PL-001 |
| Detection Source | `MFA-DET-001` Dormant MFA Method |
| Owner | SecOps IAM Team |
| Response SLA | 72 hours |
| Review Cadence | Quarterly |

## Purpose
Revoke stale default MFA methods identified by the dormant-method detection and guide users through re-registration. This reduces the risk of compromised or outdated factors remaining active.

## Preconditions
- Analyst has an active Microsoft Graph session (`Connect-MfaGraphDeviceCode`).
- Detection payload includes the user principal name and method metadata.
- Communication channel (email/phone) for reaching the affected user is available.

## High-Level Steps
1. **Validate Context** – Confirm Graph connectivity unless the operator explicitly skips validation.
2. **Notify Stakeholders** – Alert the user and SecOps queue that re-registration is required.
3. **Disable/Deregister Stale Method** – Remove or disable the default method via Graph, ensuring fallback methods remain.
4. **Trigger Re-registration** – Send instructions to the user and schedule follow-up.
5. **Ticket Update** – Document actions, capture completion timestamp, and mark the detection as resolved.

## Automation
Use `Invoke-MfaPlaybookResetDormantMethod` to orchestrate the steps with `-WhatIf`, verbose logging, and environment guardrails. The function returns a summary object suitable for downstream ticketing or reporting.

```powershell
$detection = Invoke-MfaDetectionDormantMethod -RegistrationData $registrations | Select-Object -First 1
Invoke-MfaPlaybookResetDormantMethod -Detection $detection -Verbose -WhatIf
```

## Manual Fallback
- If automation fails, follow the same steps manually in the Azure portal or via the Microsoft Graph PowerShell SDK.
- Document manual interventions in the incident ticket and flag any tooling gaps during the Phase 1 stakeholder cadence.

## Success Criteria
- Stale default method disabled or removed.
- User successfully re-registers an approved MFA factor.
- Ticket updated with remediation evidence within SLA.

