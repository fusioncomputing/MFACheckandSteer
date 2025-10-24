# Phase 5 - Response Automation & Playbook Strategy

Phase 5 translates detection insights into repeatable remediation. This document outlines the guiding principles, tooling expectations, and the playbook suite delivered alongside the detection library.

## Objectives
- Standardize SecOps remediation flows so analysts can respond quickly with guardrails.
- Provide PowerShell-first automation compatible with Windows-heavy environments.
- Capture audit trails and decision points for later reporting (Phase 6) and post-incident reviews.

## Playbook Framework
1. **Detection Input** – Playbooks accept the detection object (or summary record) returned by the Phase 4 module. This ensures framework tags, SLA data, and severity accompany every remediation run.
2. **Guardrails** – Each playbook uses `SupportsShouldProcess` with `-WhatIf`/`-Confirm` plus optional `-SkipGraphValidation` switches when needed.
3. **Logging** – Verbose messages describe each step; output objects summarize the execution plan along with whether the run was simulated.
4. **Extensibility** – Future playbooks (MFA factor reset, emergency access review, notification workflows) should follow the same pattern for consistency.

## Delivered Playbooks
- **MFA-PL-001 Reset Dormant MFA Method** – `Invoke-MfaPlaybookResetDormantMethod`; documentation in `docs/detections/playbooks/MFA-PL-001-reset-dormant-method.md`.
- **MFA-PL-002 Contain High-Risk Sign-In** – `Invoke-MfaPlaybookContainHighRiskSignin`; documentation in `docs/detections/playbooks/MFA-PL-002-contain-high-risk-signin.md`.
- **MFA-PL-003 Enforce Privileged Role MFA** – `Invoke-MfaPlaybookEnforcePrivilegedRoleMfa`; documentation in `docs/detections/playbooks/MFA-PL-003-enforce-privileged-role-mfa.md`.
- **MFA-PL-004 Triage Suspicious Activity Score** – `Invoke-MfaPlaybookTriageSuspiciousScore`; documentation in `docs/detections/playbooks/MFA-PL-004-triage-suspicious-score.md`.
- **MFA-PL-005 Contain Repeated MFA Failure Storm** – `Invoke-MfaPlaybookContainRepeatedFailure`; documentation in `docs/detections/playbooks/MFA-PL-005-contain-repeated-mfa-failure.md`.
- **MFA-PL-006 Investigate Impossible Travel Success** – `Invoke-MfaPlaybookInvestigateImpossibleTravel`; documentation in `docs/detections/playbooks/MFA-PL-006-investigate-impossible-travel.md`.

## Future Candidates
| Candidate ID | Description | Detection Link | Notes |
|--------------|-------------|----------------|-------|
| MFA-PL-007 | Service account remediation workflow | (Future detection) | Focus on non-interactive identities without MFA. |
| MFA-PL-008 | Emergency access / break-glass validation | `MFA-DET-003` (extension) | Formalize periodic review and isolation of emergency accounts. |

## Operational Guidance
- **Ticketing Integration** – Phase 5 scripts should emit objects that downstream tools (ServiceNow, Jira, Teams webhooks) can consume. Integrations will be added iteratively.
- **Documentation** – Each playbook receives a Markdown spec capturing purpose, prerequisites, and manual fallback procedures.
- **Testing** – Add scenario coverage (where practical) to `tests/MFACheckandSteer.Tests.ps1` so playbooks remain stable.
- **Change Control** – Update the controls catalog (Phase 4.6) whenever SLA expectations shift due to new automation.

## Future Enhancements
- Role-based execution controls (limiting high-impact actions to specific operators).
- Automated notification templates (email/chat) referencing detection metadata.
- Integration with device remediation workflows for compromised endpoints.
