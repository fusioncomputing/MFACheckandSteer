# Playbook MFA-PL-002 – Contain High-Risk Sign-In

| Field | Value |
|-------|-------|
| Playbook ID | MFA-PL-002 |
| Detection Source | `MFA-DET-002` High-Risk Sign-In Approved |
| Owner | SecOps Incident Response |
| Response SLA | 4 hours |
| Review Cadence | Monthly |

## Purpose
Contain and investigate risky sign-ins that succeeded with MFA despite Identity Protection alerts. The playbook provides immediate containment (session revocation, password reset), stakeholder notifications, and escalation guidance.

## Preconditions
- Analyst has an active Microsoft Graph session (`Connect-MfaGraphDeviceCode`).
- Detection payload includes user principal name, correlation ID, and risk metadata from the detection helper.
- Incident ticket or case reference is available (or generated) for audit purposes.

## High-Level Steps
1. **Validate Context** – Confirm Microsoft Graph connectivity unless the operator specifies `-SkipGraphValidation`.
2. **Revoke Sessions** – Revoke refresh tokens and sign-in sessions to prevent further abuse.
3. **Force Credential/FMF Reset** – Trigger password reset and require MFA re-registration (coordinate with IAM where needed).
4. **Notify Stakeholders** – Inform the user, seccops, and incident commander about the containment actions.
5. **Escalate Ticket** – Update or create an incident, including SLA timestamp, detection metadata, and required follow-up tasks.

## Automation
Use `Invoke-MfaPlaybookContainHighRiskSignin` to orchestrate the containment flow. The function returns an object summarizing the actions taken (or planned when `-WhatIf` is used), including SLA metadata for downstream automation.

```powershell
$detection = Invoke-MfaDetectionHighRiskSignin -SignInData $signIns | Select-Object -First 1
Invoke-MfaPlaybookContainHighRiskSignin -Detection $detection -Verbose -WhatIf
```

## Manual Fallback
- If automation fails, revoke sessions manually from the Azure portal or via identity protection tooling.
- Initiate password reset and MFA factor review through standard IAM processes.
- Document manual steps and any deviations in the incident record for later review.

## Success Criteria
- All active sessions for the compromised account revoked.
- Password reset initiated or completed; user re-proofed via secure channel.
- Detection ticket annotated with actions, timestamps, and next steps within the 4-hour SLA.

