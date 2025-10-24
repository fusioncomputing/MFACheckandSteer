# Phase 5 - Response Automation & Playbook Strategy

Phase 5 translates detection insights into repeatable remediation. This document outlines the guiding principles, tooling expectations, and the first playbook delivered in the repository.

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
- **MFA-PL-001 Reset Dormant MFA Method**  
  Guides SecOps IAM through revoking stale default methods highlighted by `MFA-DET-001`. Implemented via `Invoke-MfaPlaybookResetDormantMethod` with documentation in `docs/detections/playbooks/MFA-PL-001-reset-dormant-method.md`.
- **MFA-PL-002 Contain High-Risk Sign-In**  
  Supports SecOps Incident Response in containing risky successful sign-ins (`MFA-DET-002`) by revoking sessions, triggering resets, and escalating incidents. Implemented via `Invoke-MfaPlaybookContainHighRiskSignin` with documentation in `docs/detections/playbooks/MFA-PL-002-contain-high-risk-signin.md`.

## Next Playbooks
| Candidate ID | Description | Detection Link | Notes |
|--------------|-------------|----------------|-------|
| MFA-PL-003 | Re-enable MFA for privileged roles | `MFA-DET-003` | Validate role assignment and reapply conditional access. |
| MFA-PL-004 | Analyst runbook for suspicious score triage | `MFA-SCORE` | Convert score output into triage checklist. |

## Operational Guidance
- **Ticketing Integration** – Phase 5 scripts should emit objects that downstream tools (ServiceNow, Jira, Teams webhooks) can consume. Integrations will be added iteratively.
- **Documentation** – Each playbook receives a Markdown spec capturing purpose, prerequisites, and manual fallback procedures.
- **Testing** – Add scenario coverage (where practical) to `tests/MFACheckandSteer.Tests.ps1` so playbooks remain stable.
- **Change Control** – Update the controls catalog (Phase 4.6) whenever SLA expectations shift due to new automation.

## Future Enhancements
- Role-based execution controls (limiting high-impact actions to specific operators).
- Automated notification templates (email/chat) referencing detection metadata.
- Integration with device remediation workflows for compromised endpoints.
