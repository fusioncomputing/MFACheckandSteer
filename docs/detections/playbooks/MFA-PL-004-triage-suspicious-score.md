# Playbook MFA-PL-004 – Triage Suspicious MFA Score

| Field | Value |
|-------|-------|
| Playbook ID | MFA-PL-004 |
| Detection Source | `MFA-SCORE` Suspicious Activity Score |
| Owner | SecOps Triage Desk |
| Response SLA | 8 hours (Critical), 24 hours (High) |
| Review Cadence | Bi-weekly |

## Purpose
Provide analysts with a structured triage flow for aggregated suspicious activity scores. The playbook converts score metadata and indicators into repeatable investigation steps, escalation logic, and documentation requirements.

## Preconditions
- Suspicious activity score output from `Invoke-MfaSuspiciousActivityScore` is available (score object contains severity, indicators, and SLA metadata).
- Access to incident management tooling to record findings and escalate when thresholds are exceeded.
- Communication channel with the affected user or delegated service owner.

## High-Level Steps
1. **Prioritize Case** – Evaluate severity and SLA countdown; queue case appropriately.
2. **Inspect Indicators** – Review impossible travel, repeated failures, device anomalies, and factor changes referenced in the score.
3. **Correlate Additional Signals** – Pull recent sign-ins, Identity Protection alerts, and existing tickets.
4. **Decide Action** – Determine if containment playbooks (e.g., MFA-PL-002) must be invoked or if monitoring suffices.
5. **Document Outcome** – Update ticketing system with findings, SLA status, and next actions.

## Automation
Use `Invoke-MfaPlaybookTriageSuspiciousScore` to walk through the triage steps. The function emits a summary object noting recommended actions, escalations, and whether containment is suggested.

```powershell
$score = Invoke-MfaSuspiciousActivityScore -SignInData $signIns -RegistrationData $registrations | Select-Object -First 1
Invoke-MfaPlaybookTriageSuspiciousScore -Score $score -Verbose -WhatIf
```

## Manual Fallback
- If tool access is unavailable, manually review score indicators and log decisions in the incident record.
- Escalate immediately if SLA thresholds are at risk of breach.

## Success Criteria
- Score investigated within SLA; decision (contain, monitor, close) documented.
- Follow-on playbooks launched when required (e.g., MFA-PL-002 for containment).
- Metrics captured for reporting (number of scores triaged, containment ratio, SLA compliance).

