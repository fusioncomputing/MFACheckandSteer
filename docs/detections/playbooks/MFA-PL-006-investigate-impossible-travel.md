# Playbook MFA-PL-006 - Investigate Impossible Travel with MFA Success

| Field | Value |
|-------|-------|
| Playbook ID | MFA-PL-006 |
| Detection Source | `MFA-DET-005` Impossible Travel + MFA Success |
| Owner | SecOps Threat Hunting |
| Response SLA | 6 hours |
| Review Cadence | Monthly |

## Purpose
Investigate successful MFA sign-ins that occur from distant geographies within minutes, signalling potential token theft, session hijacking, or consent misuse. The playbook emphasizes rapid user validation, session revocation, and telemetry correlation to determine whether compromise occurred and to guide follow-up containment.

## Preconditions
- Analyst has an active Microsoft Graph session (`Connect-MfaGraphDeviceCode`) unless `-SkipGraphValidation` is used.
- Detection payload includes country/region, timestamps, and IP address metadata from `Invoke-MfaDetectionImpossibleTravelSuccess`.
- Threat hunting has access to supporting telemetry (Defender, Sentinel, SIEM) for deeper correlation.
- Operator belongs to the role assignments defined for `MFA-PL-006` in `config/playbooks.json` (exposed locally via the `MFA_PLAYBOOK_ROLES` environment variable).

## High-Level Steps
1. **Validate with the User** – Confirm whether the user legitimately travelled or recognizes the activity; escalate immediately if suspicious.
2. **Revoke Sessions** – Revoke refresh tokens and active sessions to prevent token reuse, especially when the second region is hostile.
3. **Reset Credentials & MFA** – Force password reset and require MFA re-registration with phishing-resistant methods.
4. **Review Policies** – Inspect conditional access, named locations, and travel policies for gaps that allowed the sign-in.
5. **Correlate Telemetry** – Cross-reference endpoint, network, and SIEM data to detect related malicious activity.
6. **Notify & Document** – Notify threat hunting/IR stakeholders, then update the incident record with findings and next steps.

## Automation
Run `Invoke-MfaPlaybookInvestigateImpossibleTravel` to execute the investigation workflow. The output includes execution/skip flags, SLA metadata, and sign-in context useful for dashboards or ticket enrichment.

```powershell
if (-not (Test-MfaPlaybookAuthorization -PlaybookId 'MFA-PL-006')) {
    throw 'Operator lacks required playbook role.'
}

$detection = Invoke-MfaDetectionImpossibleTravelSuccess -SignInData $signIns | Select-Object -First 1
Invoke-MfaPlaybookInvestigateImpossibleTravel -Detection $detection -Verbose -WhatIf
```

- `-NoSessionRevocation`, `-NoUserNotification`, `-NoTicketUpdate`, and `-SkipGraphValidation` switches tailor automation during exercises or when approvals are pending.

## Manual Fallback
- Revoke sessions via Azure AD portal or Identity Protection if automation is unavailable.
- Manually reset credentials and rotate app secrets; ensure the user re-registers strong MFA factors.
- Export sign-in/sentinel logs for threat hunting correlation and document all manual steps in the incident record.

## Success Criteria
- User validation (or documented attempt) plus session revocation completed within 6 hours.
- Credentials and MFA factors reset when compromise is suspected and telemetry correlation performed.
- Ticket updated with geo/IP details, remediation actions, and residual risk notes for the next review cycle.
