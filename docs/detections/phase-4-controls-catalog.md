# Phase 4.6 - Controls Catalog & Response SLAs

Roadmap task **4.6** formalizes the operational expectations tied to each detection and scoring signal. By documenting control objectives, owners, and review cadences, SecOps teams can measure performance and keep detections tuned over time.

## Objectives
- Publish a controls catalog that maps detections to owners, response SLAs, and review cadences.
- Embed SLA metadata directly in detection outputs so automation and reporting can triage by urgency.
- Provide guidance for escalating overdue detections and documenting exceptions.

## Controls Catalog

| Signal | Control Objective | Owner | Response SLA | Review Cadence | Playbook |
|--------|-------------------|-------|--------------|----------------|----------|
| `MFA-DET-001` Dormant MFA Method | Validate default factors remain current and revoke stale methods promptly. | SecOps IAM Team | 72 hours | Quarterly | `MFA-PL-001` Reset Dormant MFA Method |
| `MFA-DET-002` High-Risk Sign-In Approved | Investigate risky sign-ins that succeeded with MFA and remediate compromised factors. | SecOps Incident Response | 4 hours | Monthly | `MFA-PL-002` Contain High-Risk Sign-In |
| `MFA-SCORE` Suspicious Activity Score | Prioritize combined weak signals for analyst triage; escalate high/critical scores. | SecOps Triage Desk | 8 hours (Critical), 24 hours (High) | Bi-weekly | (Planned) MFA-PL-004 Suspicious Score Triage |

> Update this table when new detections ship (MFA-DET-003+). Owners should confirm the values during the stakeholder cadence established in Phase 1.

## SLA Enforcement Guidance
1. **Tagging:** Each detection output includes `ResponseSlaHours` plus `ControlOwner` and `ReviewCadenceDays`. Automated workflows can route alerts by owner or SLA.
2. **Tracking:** Use ticketing integrations (Phase 5) to record SLA start time when a detection is surfaced. Include the detection ID, severity, and computed score.
3. **Escalation:** If `ResponseSlaHours` is exceeded without resolution, escalate to the incident commander and note the exception in the controls register.
4. **Review Cadence:** During scheduled reviews, validate that detections remain effective, update thresholds if needed, and close out stale exceptions.

## Implementation Notes
- SLA metadata lives alongside existing framework and reporting tags in the PowerShell module, ensuring parity between documentation and runtime behavior.
- `Get-MfaDetectionConfiguration` can be extended later to support per-control SLA overrides if stakeholders request flexibility.
- Reporting dashboards (Phase 6) should surface SLA adherence metrics to track continuous improvement.

## Next Steps
1. Add controls metadata for future detections as they are designed.
2. Integrate SLA awareness into playbooks and ticketing automations in Phase 5.
3. Capture SLA breaches as part of post-incident reviews to inform tuning efforts.
