# Phase 1.3 — MFA Incident KPI Baseline

Roadmap item 1.3 requires defining measurable outcomes for MFA Check & Steer. This document captures the target key performance indicators (KPIs), baseline data collection approach, and reporting strategy so we can evaluate improvements once the project ships.

## 1. KPI Overview
| KPI | Definition | Target | Baseline Collection |
|-----|------------|--------|---------------------|
| Mean Time to Acknowledge (MTTA) | Average time from MFA alert creation to analyst acknowledgment. | ≤ 5 minutes for high-severity alerts. | Export alert timestamps and ticket acknowledgment times from SIEM/ITSM. |
| Mean Time to Remediate (MTTR) | Average time from alert creation to factor remediation or incident closure. | ≤ 60 minutes for confirmed compromises. | Correlate alert timestamps with remediation script execution logs or ticket closures. |
| False Positive Rate | Percentage of MFA alerts closed as benign/expected activity. | < 10% monthly. | Review incident categorization tags in ticketing system; sample analyst notes for accuracy. |
| Repeated Compromise Rate | Percentage of users with multiple MFA incidents in 90 days. | < 2%. | Query identity protection data and incident records for recurrence metrics. |
| Automation Coverage | Percentage of remediation actions executed via scripted runbooks vs. manual steps. | ≥ 80%. | Instrument PowerShell playbooks to emit audit events; compare against manual ticket updates. |
| Analyst Effort per Incident | Average analyst time spent (hours) per MFA incident. | < 0.5 hours. | Track time entries or use workflow automation timestamps where available. |
| User Disruption Rate | Percentage of MFA incidents causing unintended user downtime. | < 5%. | Capture user feedback post-incident; integrate with ticket follow-up forms. |
| Leadership Reporting Freshness | Age of the latest MFA status report delivered to leadership. | ≤ 7 days. | Monitor report generation job logs; verify distribution list read receipts when possible. |

## 2. Data Collection Approach
- Coordinate with SIEM/Ticketing teams to export the last 90 days of MFA-related incidents. Ensure exports include timestamps, severity, categories, and resolution notes.
- Pull Entra sign-in logs and risk detections for the same period to identify repeated compromises and correlate user risk scores.
- For automation coverage, gather historical PowerShell runbook logs (if any). If not available, run a two-week manual study where analysts track automated vs. manual actions.
- Capture qualitative feedback from analysts regarding time spent per incident to validate or supplement automated metrics.

## 3. Baseline Establishment Steps
1. Define alert taxonomy: map which alert types (e.g., impossible travel, repeated failures) are considered in-scope for MFA incidents.
2. Extract historical data and calculate the KPIs; store calculations in a secure analytics workspace (e.g., Power BI dataset, Excel tracker).
3. Review results with SecOps leadership to confirm targets are realistic and aligned with organizational goals.
4. Document any data quality caveats (missing timestamps, inconsistent tagging) and plan remediation (automation training, process updates).

## 4. Reporting & Governance
- Present baseline KPI results during the Phase 1 charter sign-off meeting.
- Establish a dashboard (Power BI or Grafana) refreshed weekly to track progress over time.
- Assign KPI owners (e.g., SecOps operations manager) responsible for monitoring changes and escalating regressions.
- Include KPI snapshots in the bi-weekly stakeholder cadence (Phase 1.6) and release readiness reviews (Phase 7.5).

## 5. Open Questions
- Are there existing BI dashboards we should extend instead of building new ones?
- Do current systems support tagging automation usage, or is a workflow change required?
- Should user disruption be captured via automated surveys (e.g., Forms) immediately after incidents?
