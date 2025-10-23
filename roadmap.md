# MFA Check & Steer - Roadmap

## Phase 1 - SecOps Discovery & Charter
- 1.1 Interview SecOps analysts and incident commanders to capture current MFA triage workflows, toolchains, and pain points.
- 1.2 Map existing MFA signal sources (Azure AD sign-in logs, conditional access, VPN, custom IdPs, and SIEM exports) and document data retention constraints.
- 1.3 Define prioritized SecOps outcomes (reduced escalations, faster mean time to revoke compromised factors) and measurable KPIs for success.
- 1.4 Document compliance requirements and data-handling classifications for MFA artifacts stored or processed by the tool.
- 1.5 Produce an agreed charter covering scope boundaries, supported environments (PowerShell-first), and success metrics signed off by stakeholders.
- 1.6 Establish a stakeholder alignment cadence (bi-weekly SecOps sync, RFC checkpoints) and assign a single charter owner responsible for updating decisions and action items.

## Phase 2 - Foundation & Tooling
- 2.1 Finalize the technology stack (PowerShell module with optional .NET service components) and directory layout optimized for Windows execution.
- 2.2 Configure repository automation: `.gitattributes` for line endings, Pester unit test harness, PSScriptAnalyzer linting, Invoke-Formatter formatting, and CI-friendly PowerShell scripts.
- 2.3 Author developer environment bootstrap scripts (`setup.ps1`) that install prerequisites, import required modules, and validate permissions/certificates.
- 2.4 Establish GitHub Actions workflows on Windows runners for unit tests, security scanning, artifact packaging, and release gating.
- 2.5 Implement secure secret-handling patterns (configuration templates, integration guidance for Windows Credential Manager or Azure Key Vault) for local and CI environments.
- 2.6 Add environment validation gates: smoke-test scripts on fresh Windows VMs/containers, capture known limitations, and maintain a dependency matrix (PowerShell/.NET/modules).

## Phase 3 - Data Acquisition & Normalization
- 3.1 Implement connectors for primary MFA providers (Azure AD/Entra, Okta, Duo, on-prem RADIUS) using vendor-supported PowerShell APIs/Graph endpoints.
- 3.2 Normalize ingested events into a canonical schema with consistent factor metadata, tenant identifiers, timestamps, and severity levels.
- 3.3 Provide sample datasets and replay scripts to enable offline development, automated regression tests, and documentation examples.
- 3.4 Build resiliency into ingestion: handle pagination, throttling, transient failures, and logging/telemetry for data pipeline health.
- 3.5 Document source-specific prerequisites, least-privilege RBAC roles, and configuration checklists to help SecOps onboard new tenants quickly.
- 3.6 Deliver connectors iteratively (Provider v1 slices) with acceptance tests, shared schema contracts, and standardized logging conventions to ease future integrations.

## Phase 4 - Risk Analysis & Detection Library
- 4.1 Develop detection rules that flag risky MFA configurations (disabled enforcement, weak fallback factors, bypass policies, dormant accounts).
- 4.2 Implement suspicious activity scoring that correlates impossible travel, repeated failures, unusual device fingerprints, and high-risk factor changes.
- 4.3 Map detections to frameworks (MITRE ATT&CK, NIST CSF) and produce reporting tags to simplify compliance reporting.
- 4.4 Create unit/integration tests plus synthetic incident scenarios that validate detection coverage via PowerShell-driven harnesses.
- 4.5 Provide configuration options and documentation for tuning thresholds while preserving sensible defaults and guardrails.
- 4.6 Maintain a controls catalog mapped to risk severities, and define SLAs for reviewing false positives and tuning detection thresholds with SecOps owners.

## Phase 5 - Response Automation & Playbooks
- 5.1 Design remediation playbooks (PowerShell functions) to disable or reset factors, enforce step-up authentication, and notify affected users with approval workflows.
- 5.2 Include guardrails: what-if modes, verbose logging, confirmation prompts, and rollback guidance to prevent accidental lockouts.
- 5.3 Implement role-based controls within scripts, ensuring only authorized SecOps identities can execute high-impact actions.
- 5.4 Integrate with ticketing/ITSM platforms (ServiceNow, Jira) and collaboration tools (Teams, Slack) to automate case creation, updates, and closures with audit trails.
- 5.5 Document operational runbooks for analysts, including triage checklists, escalation paths, and post-incident reporting templates.
- 5.6 Schedule regular tabletop and live-fire playbook drills, and capture metrics (MTTR reduction, remediation success rate) to demonstrate automation effectiveness.

## Phase 6 - Reporting, UX, and Knowledge Sharing
- 6.1 Build PowerShell CLI dashboards that summarize MFA posture, outstanding risks, and remediation progress with CSV/JSON export options.
- 6.2 Provide scheduled reporting scripts that distribute summaries via email or chat, and embed results into existing SecOps dashboards/SIEMs.
- 6.3 Author comprehensive documentation packs: getting started, architecture overview, troubleshooting, security considerations, and FAQ.
- 6.4 Produce training materials (recorded demos, labs, tabletop scenarios) to onboard analysts and measure readiness.
- 6.5 Establish feedback loops (issue templates, RFC process, stakeholder review cadence) so SecOps teams can request enhancements effectively.
- 6.6 Run UX research checkpoints (interviews, usability tests), document accessibility expectations, and perform internal documentation peer reviews before publishing.

## Phase 7 - Hardening, Compliance, and Release
- 7.1 Run end-to-end security reviews: static code analysis, dependency audits, credential hygiene validation, and threat modeling refresh.
- 7.2 Execute performance and scale testing on large tenant datasets, optimizing PowerShell execution through parallelism where safe.
- 7.3 Validate disaster recovery and retention: backup/restore configurations, verify audit logs meet policy, and ensure tamper-evident storage.
- 7.4 Finalize packaging (versioned PowerShell module, signed scripts, release notes) and distribution guidance for SecOps deployment.
- 7.5 Plan pilot rollouts, collect feedback, iterate on findings, and publish GA release with support handbook and maintenance schedule.
- 7.6 Rehearse incident response for the tool itself, enforce script/code signing policies, and maintain a post-release backlog for dependency updates and patch cadence.
