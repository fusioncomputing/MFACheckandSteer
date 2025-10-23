# MFA Check & Steer — Roadmap

## Phase 0 - SecOps Discovery & Charter
- Interview SecOps analysts and incident commanders to capture current MFA triage workflows, toolchains, and pain points.
- Map existing MFA signal sources (Azure AD sign-in logs, conditional access, VPN, custom IdPs, and SIEM exports) and document data retention constraints.
- Define prioritized SecOps outcomes (reduced escalations, faster mean time to revoke compromised factors) and measurable KPIs for success.
- Document compliance requirements and data-handling classifications for MFA artifacts stored or processed by the tool.
- Produce an agreed charter covering scope boundaries, supported environments (PowerShell-first), and success metrics signed off by stakeholders.
- Establish a stakeholder alignment cadence (bi-weekly SecOps sync, RFC checkpoints) and assign a single charter owner responsible for updating decisions and action items.

## Phase 1 - Foundation & Tooling
- Finalize the technology stack (PowerShell module with optional .NET service components) and directory layout optimized for Windows execution.
- Configure repository automation: `.gitattributes` for line endings, Pester unit test harness, PSScriptAnalyzer linting, Invoke-Formatter formatting, and CI-friendly PowerShell scripts.
- Author developer environment bootstrap scripts (`setup.ps1`) that install prerequisites, import required modules, and validate permissions/certificates.
- Establish GitHub Actions workflows on Windows runners for unit tests, security scanning, artifact packaging, and release gating.
- Implement secure secret-handling patterns (configuration templates, integration guidance for Windows Credential Manager or Azure Key Vault) for local and CI environments.
- Add environment validation gates: smoke-test scripts on fresh Windows VMs/containers, capture known limitations, and maintain a dependency matrix (PowerShell/.NET/modules).

## Phase 2 - Data Acquisition & Normalization
- Implement connectors for primary MFA providers (Azure AD/Entra, Okta, Duo, on-prem RADIUS) using vendor-supported PowerShell APIs/Graph endpoints.
- Normalize ingested events into a canonical schema with consistent factor metadata, tenant identifiers, timestamps, and severity levels.
- Provide sample datasets and replay scripts to enable offline development, automated regression tests, and documentation examples.
- Build resiliency into ingestion: handle pagination, throttling, transient failures, and logging/telemetry for data pipeline health.
- Document source-specific prerequisites, least-privilege RBAC roles, and configuration checklists to help SecOps onboard new tenants quickly.
- Deliver connectors iteratively (Provider v1 slices) with acceptance tests, shared schema contracts, and standardized logging conventions to ease future integrations.

## Phase 3 - Risk Analysis & Detection Library
- Develop detection rules that flag risky MFA configurations (disabled enforcement, weak fallback factors, bypass policies, dormant accounts).
- Implement suspicious activity scoring that correlates impossible travel, repeated failures, unusual device fingerprints, and high-risk factor changes.
- Map detections to frameworks (MITRE ATT&CK, NIST CSF) and produce reporting tags to simplify compliance reporting.
- Create unit/integration tests plus synthetic incident scenarios that validate detection coverage via PowerShell-driven harnesses.
- Provide configuration options and documentation for tuning thresholds while preserving sensible defaults and guardrails.
- Maintain a controls catalog mapped to risk severities, and define SLAs for reviewing false positives and tuning detection thresholds with SecOps owners.

## Phase 4 - Response Automation & Playbooks
- Design remediation playbooks (PowerShell functions) to disable or reset factors, enforce step-up authentication, and notify affected users with approval workflows.
- Include guardrails: what-if modes, verbose logging, confirmation prompts, and rollback guidance to prevent accidental lockouts.
- Implement role-based controls within scripts, ensuring only authorized SecOps identities can execute high-impact actions.
- Integrate with ticketing/ITSM platforms (ServiceNow, Jira) and collaboration tools (Teams, Slack) to automate case creation, updates, and closures with audit trails.
- Document operational runbooks for analysts, including triage checklists, escalation paths, and post-incident reporting templates.
- Schedule regular tabletop and live-fire playbook drills, and capture metrics (MTTR reduction, remediation success rate) to demonstrate automation effectiveness.

## Phase 5 - Reporting, UX, and Knowledge Sharing
- Build PowerShell CLI dashboards that summarize MFA posture, outstanding risks, and remediation progress with CSV/JSON export options.
- Provide scheduled reporting scripts that distribute summaries via email or chat, and embed results into existing SecOps dashboards/SIEMs.
- Author comprehensive documentation packs: getting started, architecture overview, troubleshooting, security considerations, and FAQ.
- Produce training materials (recorded demos, labs, tabletop scenarios) to onboard analysts and measure readiness.
- Establish feedback loops (issue templates, RFC process, stakeholder review cadence) so SecOps teams can request enhancements effectively.
- Run UX research checkpoints (interviews, usability tests), document accessibility expectations, and perform internal documentation peer reviews before publishing.

## Phase 6 - Hardening, Compliance, and Release
- Run end-to-end security reviews: static code analysis, dependency audits, credential hygiene validation, and threat modeling refresh.
- Execute performance and scale testing on large tenant datasets, optimizing PowerShell execution through parallelism where safe.
- Validate disaster recovery and retention: backup/restore configurations, verify audit logs meet policy, and ensure tamper-evident storage.
- Finalize packaging (versioned PowerShell module, signed scripts, release notes) and distribution guidance for SecOps deployment.
- Plan pilot rollouts, collect feedback, iterate on findings, and publish GA release with support handbook and maintenance schedule.
- Rehearse incident response for the tool itself, enforce script/code signing policies, and maintain a post-release backlog for dependency updates and patch cadence.
