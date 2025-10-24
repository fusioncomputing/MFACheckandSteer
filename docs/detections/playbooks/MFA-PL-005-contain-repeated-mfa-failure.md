# Playbook MFA-PL-005 - Contain Repeated MFA Failure Storm

| Field | Value |
|-------|-------|
| Playbook ID | MFA-PL-005 |
| Detection Source | `MFA-DET-004` Repeated MFA Failures |
| Owner | SecOps Incident Response |
| Response SLA | 8 hours |
| Review Cadence | Monthly |

## Purpose
Quickly contain bursts of MFA denials that typically signal password spraying, MFA fatigue, or script-driven probing. The playbook coordinates user validation, temporary access controls, credential resets, and follow-up monitoring so analysts can shut down the activity while documenting actions for audit.

## Preconditions
- Analyst is authenticated to Microsoft Graph (`Connect-MfaGraphDeviceCode`) unless `-SkipGraphValidation` is used.
- Detection payload includes the affected user, failure counts, and window timestamps from `Invoke-MfaDetectionRepeatedMfaFailure`.
- Incident tracking (ticket or case) is available to capture remediation evidence.
- Operator belongs to the role assignments defined for `MFA-PL-005` in `config/playbooks.json` (export via the `MFA_PLAYBOOK_ROLES` environment variable when running locally).

## High-Level Steps
1. **Engage the User** – Confirm with the user (and manager/security contacts) whether the surge of prompts was legitimate or malicious.
2. **Temporarily Block Sign-In** – Apply a temporary sign-in block or equivalent guardrail until resets are completed.
3. **Reset Credentials** – Trigger password reset and enforce MFA re-registration with phishing-resistant methods.
4. **Investigate Sources** – Review sign-in telemetry, Identity Protection, and network logs for the originating IPs/devices and create containment rules as needed.
5. **Update Ticket & Monitor** – Record all actions, note SLA timestamps, and schedule follow-up monitoring for recurring failures.

## Automation
Use `Invoke-MfaPlaybookContainRepeatedFailure` to orchestrate the containment activities. The output object includes SLA metadata, executed steps, and containment flags that downstream automations can consume.

```powershell
if (-not (Test-MfaPlaybookAuthorization -PlaybookId 'MFA-PL-005')) {
    throw 'Operator lacks required playbook role.'
}

$detection = Invoke-MfaDetectionRepeatedMfaFailure -SignInData $signIns | Select-Object -First 1
Invoke-MfaPlaybookContainRepeatedFailure -Detection $detection -Verbose -WhatIf
```

- `-NoUserNotification`, `-NoTicketUpdate`, and `-NoUserBlock` switches allow tailored execution during exercises or when approvals are pending.
- `-SkipGraphValidation` bypasses the Graph context check (useful for dry runs or offline reviews).

## Manual Fallback
- Block sign-in and reset credentials using Azure Portal or IAM tooling if automation is unavailable.
- Export sign-in logs and provide indicators (IP addresses, device identifiers) to network defenders for additional blocking.
- Document all manual steps in the ticket, including timestamps and escalation notes.

## Success Criteria
- User is contacted (or documented attempt) and sign-in blocked or high-risk password reset initiated within the 8-hour SLA.
- MFA factors re-proofed, and monitoring scheduled to confirm attacks cease.
- Ticket contains remediation details, SLA compliance evidence, and any residual risk notes for the next review.
