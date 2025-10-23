# Phase 1.1 — SecOps Stakeholder Interview Plan

This plan targets roadmap item **1.1**: “Interview SecOps analysts and incident commanders to capture current MFA triage workflows, toolchains, and pain points.” It outlines who we need to speak with, how we prepare, and which questions to ask. For each question, we include a “Best-Practice Answer” that captures the target state we want to drive toward; deviations during interviews will highlight gaps we must address.

## 1. Stakeholder Personas & Targets
| Persona | Example Roles | Interview Goals |
|---------|---------------|-----------------|
| SecOps Analyst | SOC Tier 1/2 Analyst, Security Engineer | Understand day-to-day MFA alert handling, tooling friction, required telemetry. |
| Incident Commander | IR Lead, Defensive Operations Manager | Capture escalation triggers, cross-team handoffs, KPIs, reporting expectations. |
| Identity Administrator | Azure AD Admin, IAM Engineer | Validate identity platform constraints, policy management workflows, admin tooling. |
| Compliance / Governance | GRC Analyst, Audit Liaison | Elicit retention requirements, evidence needs, and approved workflows. |
| Automation Platform Owner | DevOps Engineer, SecOps tooling lead | Determine CI/CD, scripting standards, credential management expectations. |

Target at least one representative for each persona. Prefer diverse coverage across shifts/regions to capture operational variance.

## 2. Logistics & Cadence
- Schedule 45-minute interviews over the next two weeks; cluster related personas to spot shared themes quickly.
- Use a shared OneNote/Teams notebook for raw notes; summarize key findings in `docs/interview-summaries/` (create per persona group).
- Record (with permission) to capture nuanced details; store recordings in an approved secure location for 30 days, then delete.
- After each interview day, host a 15-minute debrief to align on emerging patterns and prep follow-up questions.

## 3. Interview Question Bank with Best-Practice Answers

| # | Question | Purpose | Best-Practice Answer (Target State) |
|---|----------|---------|-------------------------------------|
| 1 | Describe your current workflow when an MFA alert triggers. Which systems do you open first? | Map baseline triage flow. | Analysts pivot from SIEM alert → Entra sign-in logs dashboard → ticketing system within 5 minutes, aided by bookmarked runbooks and scripted queries. |
| 2 | How do you determine if an MFA prompt was malicious or expected? | Identify decision criteria. | Correlate login context (IP, device, conditional access result) with user verification via automated notification; rely on enriched context from identity protection and user risk scoring. |
| 3 | What data sources or views are missing when you troubleshoot MFA incidents? | Surface telemetry gaps. | All required context (sign-in details, authentication method history, policy evaluations) appears in a single workspace; missing sources are rare and documented. |
| 4 | Which actions do you take to contain or remediate a compromised factor? | Understand response playbooks. | Use scripted PowerShell runbooks with approval workflow to disable/reset factor, enforce password change, and notify user + manager; steps logged automatically. |
| 5 | Where do escalations typically occur, and how are they communicated? | Pinpoint handoff pain points. | Clear escalation matrix; incidents move from Tier 1 to Incident Commander via ticket workflow with structured data; SLAs documented and met. |
| 6 | What KPIs or metrics do you track for MFA incidents? | Validate measurement. | Track MTTA/MTTR, rate of successful factor resets, number of false positives, and recurring user friction; reported weekly to leadership. |
| 7 | Are there manual or repetitive tasks you believe should be automated? | Identify automation opportunities. | Only edge cases remain manual; standard tasks (data pull, user contact, ticket updates) automated through scripts or integrations. |
| 8 | How do you coordinate with identity admins when policy changes are required? | Examine cross-team collaboration. | Joint change advisory board, shared backlog, and review cadence; changes rolled out via infrastructure-as-code with staged testing. |
| 9 | What retention or compliance requirements affect your ability to store MFA data? | Capture governance constraints. | Policies documented; sign-in logs retained per regulation (e.g., 1 year) via approved storage; access audited; privacy impact assessments completed. |
|10| Which credentials or accounts do you use for investigation tooling? | Assess security hygiene. | Use least-privilege, dedicated SecOps accounts with MFA enforced; automation uses managed identities/service principals with conditional access controls. |
|11| What training or runbooks support new analysts handling MFA incidents? | Gauge onboarding maturity. | Up-to-date runbooks with annotated playbooks, scenario-based training, and quarterly refreshers; tracked completion in LMS. |
|12| How satisfied are you with current reporting to leadership on MFA posture? | Understand executive needs. | Leadership receives automated weekly reports with actionable insights, trend analysis, and remediation status; feedback loop ensures relevance. |
|13| What is the biggest risk or pain point regarding MFA today? | Prioritize roadmap focus. | Only residual, low-impact issues remain; critical gaps (e.g., attack detection delays) are resolved quickly through continuous improvement. |
|14| If you could change one part of the MFA response process tomorrow, what would it be? | Capture quick wins. | Minor UX improvements such as consolidated dashboards or improved user notifications; major blockers already addressed. |

During interviews, note departures from the best-practice column—those become requirements or backlog items.

## 4. Pre-Interview Preparation
- Send agenda and question list to participants 24 hours ahead to encourage thoughtful answers.
- Confirm required access (Teams/Zoom, recording permissions) and gather sample incident data that can be discussed safely.
- Provide context on MFA Check & Steer objectives so stakeholders understand purpose and scope.

## 5. Post-Interview Actions
- Summarize findings within 24 hours; tag each insight with related roadmap items (e.g., 3.1 connectors, 5.4 ITSM integration).
- Feed pain points into the product backlog and identify quick wins vs. long-term epics.
- Update `agents.md` with any new operating constraints or tooling requirements uncovered.
- Share a consolidated insights deck during the next stakeholder cadence meeting (Phase 1.6).

## 6. Open Follow-Ups
- Validate interview availability for each persona; track in a shared calendar.
- Confirm data handling protocols for recordings and notes with Compliance before the first session.
- Identify a neutral facilitator (product manager or SecOps liaison) to run each interview while the engineering lead captures notes.
