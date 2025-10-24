# Phase 4.1 — MFA Detection Strategy

This document defines the initial detection philosophy, rule catalog, and development process for MFA Check & Steer. It satisfies roadmap task **4.1**.

## Detection Objectives
- Surface risky MFA configurations that increase the chance of account takeover.
- Highlight suspicious authentication activity requiring analyst review.
- Provide actionable context that maps directly to response playbooks (Phase 5).
- Minimize false positives by leveraging normalized data and tunable thresholds.

## Data Inputs
- **Canonical Sign-In Records** (`Get-MfaEntraSignIn -Normalize`) — Provide per-authentication context including conditional access status and risk signals.
- **Canonical Registration Records** (`Get-MfaEntraRegistration -Normalize`) — Track factor types, default status, and method freshness.
- **Configuration Snapshots** (future) — Conditional access policies, MFA registration enforcement settings.
- **External Signals** (optional) — SIEM alerts, threat intelligence feeds (Phase 3+ extensibility).

## Detection Rule Catalog (Initial Set)
| ID | Name | Severity | Data Inputs | Summary |
|----|------|----------|-------------|---------|
| MFA-DET-001 | Dormant MFA Method | Medium | Registration records | Flag users whose default method has not been updated/used in 90+ days. |
| MFA-DET-002 | High-Risk Sign-In Approved | High | Sign-in records | Detect high-risk sign-ins (risk state `atRisk`) that still succeeded with MFA. |
| MFA-DET-003 | MFA Disabled for Privileged Role | Critical | Registration records + role assignment (Phase 3 extension) | Identify privileged identities lacking any active MFA method. |
| MFA-DET-004 | Repeated MFA Failures | Medium | Sign-in records | Trigger when a user experiences > `N` MFA failures within `T` minutes. |
| MFA-DET-005 | Impossible Travel + MFA Success | High | Sign-in records | Combine impossible travel detection output with successful MFA to prompt review for MFA fatigue attacks. |

## Suspicious Activity Scoring (Phase 4.2)
In addition to discrete detections, Phase 4 introduces an aggregate scoring helper (`Invoke-MfaSuspiciousActivityScore`) that correlates multiple weak signals—impossible travel, repeated failures, unfamiliar devices, and recent MFA factor downgrades. The scoring model and weights are documented in `docs/detections/phase-4-suspicious-activity-scoring.md` and provide a prioritization layer for SecOps queues.

## Framework Alignment & Reporting Tags (Phase 4.3)
Roadmap task 4.3 adds governance context by mapping detections to MITRE ATT&CK, NIST CSF, and standardized reporting tags. Refer to `docs/detections/phase-4-framework-mapping.md` for canonical mappings that must be reflected in code and documentation.

## Synthetic Incident Scenarios (Phase 4.4)
To validate detections end-to-end, Phase 4.4 introduces curated scenarios captured in `docs/detections/phase-4-incident-scenarios.md`, with corresponding datasets under `data/scenarios/` and the replay harness `scripts/replay-scenarios.ps1`.

## Detection Configuration & Tuning (Phase 4.5)
Phase 4.5 formalizes configurable thresholds and guardrails via `config/detections.json`. The module exposes helpers to retrieve merged defaults, and detections automatically respect overrides unless parameters are supplied explicitly. See `docs/detections/phase-4-configuration.md` for guidance.

## Controls Catalog & SLAs (Phase 4.6)
Operational responsibilities are documented in `docs/detections/phase-4-controls-catalog.md`, aligning each detection and score with control owners, response SLAs, and review cadences. Detection outputs surface the same metadata so automation and reporting can enforce timelines and escalations.

> As the library grows, detections will be grouped by category (Configuration, Authentication Activity, Threat Correlation).

## Rule Specification Template (stored under `docs/detections/rules/`)
Each rule file will contain:
1. **Metadata** — ID, name, severity, owner, last review date.
2. **Description** — Problem statement and rationale.
3. **Data Requirements** — Tables/dataframes needed (normalized format references).
4. **Logic** — Pseudocode or query (PowerShell, Kusto, etc.) with tunable parameters.
5. **Considerations** — Known limitations, false positive tuning guidance.
6. **Response Mapping** — Linked playbooks (Phase 5).
7. **Testing** — Reference to sample datasets or unit tests.

## Development Process
1. Draft the detection spec in `docs/detections/rules/`.
2. Implement PowerShell detection logic (e.g., `Invoke-MfaDetectionDormantMethod`) under `src/` with unit tests in `tests/`.
3. Add sample events to `data/samples/` if needed to demonstrate detection triggers.
4. Update release checklist and rule catalog summary.

## Acceptance Criteria for Phase 4.1
- Strategy documented (this file).
- Detection catalog with at least five candidate rules and severity mapping.
- Rule template established under `docs/detections/rules/`.
- Repository structure updated to accommodate detection documentation and tests.
- Next steps outlined for implementing the first detection (likely MFA-DET-002 or MFA-DET-004).

## Next Actions
1. Extend sample datasets to include positive/negative cases for each detection and integrate with automated regression tests. (Initial coverage added for Phase 4.2 scoring scenarios.)
2. Publish rule specs for MFA-DET-003 through MFA-DET-005 following the established template.
3. Wire detections and aggregated scores into reporting outputs (e.g., summary dashboards) and map to response playbooks in Phase 5. (Phase 4.3 mappings supply framework and reporting tags for automation.)
4. Maintain synthetic incident scenarios alongside new detections to ensure regression coverage across evolving telemetry inputs.
5. Track configuration changes and ensure overrides remain consistent with documented guardrails (Phase 4.5).
6. Incorporate SLA metrics into ticketing and dashboards, escalating overdue detections per the controls catalog (Phase 4.6).
7. Extend detection library with operational playbooks and additional specs (MFA-DET-003 now documented; MFA-DET-004/005 pending).
