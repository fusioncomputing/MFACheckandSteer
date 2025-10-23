# Phase 1.5 — MFA Check & Steer Project Charter

This charter summarizes the scope, objectives, and governance for the MFA Check & Steer initiative. It satisfies roadmap item 1.5.

## 1. Executive Summary
MFA Check & Steer delivers PowerShell-first tooling that helps SecOps teams detect, triage, and remediate risky MFA activity quickly. The project streamlines data ingestion from Microsoft Entra MFA, automates response playbooks, and provides actionable reporting for leadership—reducing incident response times and improving MFA posture visibility.

## 2. Objectives & Success Metrics
- Reduce Mean Time to Acknowledge (MTTA) high-severity MFA alerts to ≤ 5 minutes.
- Cut Mean Time to Remediate (MTTR) confirmed MFA compromises to ≤ 60 minutes.
- Decrease false positive rate for MFA alerts below 10% monthly.
- Achieve ≥ 80% automation coverage for standard remediation actions.
- Deliver leadership-ready reporting refreshed within 7 days of run.

## 3. Scope
### In Scope
- Microsoft Entra (Azure AD) MFA telemetry ingestion, normalization, and reporting.
- PowerShell runbooks for MFA investigation and remediation workflows.
- Integration with existing ticketing/ITSM and collaboration tools (ServiceNow, Jira, Teams, Slack).
- Security governance documentation (compliance classification, audit logs, incident runbooks).

### Out of Scope (Phase 1–Phase 4)
- Support for non-Entra MFA providers. (Future roadmap item once initial release stabilizes.)
- Development of full GUI application (CLI and dashboard exports only).
- On-premises-only environments without Azure AD Graph/Log Analytics access.

## 4. Deliverables
- Detailed roadmap with numbered phases and tasks.
- Stakeholder interview findings and SecOps workflow maps.
- Entra MFA signal mapping documentation.
- Baseline KPI report and compliance classification plan.
- PowerShell tooling (modules, scripts) with tests and CI/CD pipeline.
- Response playbooks, runbooks, and leadership reporting templates.

## 5. Timeline & Milestones (High-Level)
- Phase 1 (Discovery & Charter): Completed by end of Month 1.
- Phase 2–3 (Foundation & Data Acquisition): Months 2–3.
- Phase 4–5 (Detection & Response Automation): Months 4–5.
- Phase 6–7 (Reporting, Hardening, Release): Month 6.
*Detailed sprint plan to be established with SecOps product owner.*

## 6. Roles & Responsibilities
- **Executive Sponsor:** CISO/CISO delegate — removes roadblocks, approves scope changes.
- **Product Owner:** SecOps Lead — prioritizes backlog, owns stakeholder cadence.
- **Technical Lead:** Identity Security Engineer — architect for PowerShell tooling and integrations.
- **Compliance Liaison:** GRC Analyst — validates data handling and retention requirements.
- **Automation Engineer(s):** PowerShell developer(s) — build connectors, runbooks, CI/CD.
- **Incident Response Representative:** Incident Commander — ensures playbooks align with operations.

## 7. Governance & Communication
- Bi-weekly stakeholder sync (see Phase 1.6) reviewing progress, risks, KPIs.
- RFC process for major changes; proposals stored in `docs/rfcs/` with 1-week review window.
- Shared Teams/Slack channel with SecOps and engineering for day-to-day coordination.
- Monthly executive summary highlighting KPI trends, risks, and upcoming milestones.

## 8. Risks & Mitigations
| Risk | Impact | Mitigation |
|------|--------|------------|
| Delayed access to production Entra logs | Slows connector development | Secure sandbox tenant; prioritize service principal provisioning early. |
| Insufficient SecOps availability for interviews/testing | Requirements gaps | Schedule interviews early; provide async questionnaires; secure leadership support. |
| Compliance approvals delay automation rollout | Blocks release | Engage GRC from Phase 1; deliver PIA and retention plan early for review. |
| Tooling divergence from analyst workflows | Low adoption | Involve analysts in usability testing and pilot programs; iterate quickly on feedback. |

## 9. Approval
| Role | Name | Signature | Date |
|------|------|-----------|------|
| Executive Sponsor | TBA |  |  |
| Product Owner | TBA |  |  |
| Technical Lead | TBA |  |  |
| Compliance Liaison | TBA |  |  |
