# Phase 4.3 - Framework Alignment & Reporting Tags

Roadmap task **4.3** ensures every detection produced by MFA Check & Steer aligns with recognized control frameworks and exposes reporting tags for downstream analytics, dashboards, and compliance evidence.

## Alignment Objectives
- Provide immediate context for SecOps analysts by mapping detections to relevant MITRE ATT&CK techniques, NIST CSF categories, and internal control identifiers.
- Standardize reporting tags so dashboards, SIEM forwarding rules, and ticketing integrations can group detections without re-implementing logic.
- Keep mappings versioned in-source to simplify audits and future changes.

## Detection Mapping Catalog

| Detection ID | MITRE ATT&CK | NIST CSF | Reporting Tags | Notes |
|--------------|--------------|----------|----------------|-------|
| MFA-DET-001 Dormant MFA Method | `T1078` (Valid Accounts) | `PR.AC-1`, `PR.AC-6` | `Configuration`, `MFA`, `DormantMethod`, `Risk-Medium` | Dormant factors expand the attack surface for valid account abuse. |
| MFA-DET-002 High-Risk Sign-In Approved | `T1110.003` (Password Spraying), `T1621` (Multi-Factor Authentication Interception) | `DE.AE-2`, `DE.CM-7` | `Authentication`, `HighRiskSignin`, `Risk-High` | Identity Protection sign-ins with MFA success signal MFA fatigue/factor compromise. |
| MFA-Score Suspicious Activity | `T1110`, `T1078`, `T1621` (as applicable) | `DE.AE-2`, `DE.AE-3`, `DE.CM-1` | `Aggregated`, `SuspiciousScore`, `Risk-{Severity}` | Aggregated scoring surfaces combined weak signals; severity suffix mirrors computed tier. |

> Future detections (MFA-DET-003+) must extend this table as they are authored. Internal control IDs can reference your organization's GRC library if available.

## Reporting Tag Conventions
- Tags are emitted as ordered string arrays in detection/scoring output.
- Prefix controls (optional) with `Risk-`, `Source-`, or `Action-` to simplify downstream filtering.
- Severity tags (`Risk-Low`, `Risk-Medium`, `Risk-High`, `Risk-Critical`) always reflect the detection's `Severity` field.
- Consuming systems can safely treat tags as case-insensitive.

## Implementation Guidance
1. Maintain the canonical mapping inside the PowerShell module (see `Get-MfaDetectionMetadata` helper) to ensure runtime outputs stay consistent with documentation.
2. Update detection functions to append `FrameworkTags`, `NistFunctions`, and `ReportingTags` to each emitted object.
3. Add unit tests validating the metadata for every detection and scoring helper.
4. Reference this document from `docs/detections/detection-strategy.md` and detection specs to keep documentation synchronized.

## Future Enhancements
- Extend mappings to include CIS Controls, ISO 27001, or other frameworks used by stakeholders.
- Publish the catalog as JSON for integration with reporting pipelines in Phase 6.
- Incorporate confidence levels and remediation SLAs alongside tags for richer automation hooks.

