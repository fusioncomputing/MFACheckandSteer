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
1. Create rule spec files for MFA-DET-001 and MFA-DET-002.
2. Implement detection evaluation helpers in PowerShell that operate on canonical datasets.
3. Add automated tests ensuring detection functions correctly identify positive and negative cases using sample data.
