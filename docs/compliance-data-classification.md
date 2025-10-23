# Phase 1.4 — Compliance & Data Classification Requirements

Roadmap item 1.4 calls for documenting compliance obligations and data-handling rules for MFA telemetry. This guide consolidates the relevant standards, classifications, and storage expectations.

## 1. Applicable Regulations & Frameworks
- **Organization Policies:** Confirm internal security policy, data retention policy, and incident response standards (e.g., SEC-IR-01, DATA-RET-02).
- **Industry Regulations:** Depending on business units, consider: SOC 2 Type II, ISO 27001, HIPAA (if healthcare), PCI DSS (for payment data), and GDPR/UK GDPR for EU data subjects.
- **Microsoft Licensing Terms:** Review Microsoft Entra (Azure AD) licensing to ensure log exports align with permitted use.

## 2. Data Classification Categories
| Category | Description | MFA Artifacts | Handling Requirements |
|----------|-------------|---------------|-----------------------|
| Restricted (Confidential) | Sensitive personal or security data with strict access controls. | Sign-in logs (contain PII, IPs), risk detections, authentication methods. | Store in encrypted-at-rest locations, limit access to SecOps and IAM, enforce MFA. |
| Internal | Operational data with moderate sensitivity. | Runbook execution logs, automation coverage metrics. | Accessible within corporate network; audit access quarterly. |
| Public | Non-sensitive info. | Documentation, sanitized training samples. | May be shared externally in redacted form. |

## 3. Retention & Storage
- **Sign-in & audit logs:** Minimum 1 year retention (align with security policy). Use Log Analytics workspace with configurable retention + archiving to Azure Storage for long-term needs (up to 7 years if required by compliance).
- **Ticketing records:** Retain per incident response policy (typically 2-5 years). Ensure references to MFA incidents are tagged for discovery.
- **Training datasets:** Maintain sanitized samples; delete raw PII exports after usage. Document approval for retaining any anonymized datasets beyond 90 days.

## 4. Access Controls & Monitoring
- Enforce role-based access (RBAC): SecOps analysts (read), IAM admins (read/write policies), Compliance (read). Automation service principals should have least-privilege Graph permissions.
- Require conditional access (compliant device + MFA) for all accounts viewing restricted MFA data.
- Enable audit logging for data access; review quarterly for anomalies.
- Implement data loss prevention (DLP) monitoring for channels where MFA telemetry might be shared (email, Teams).

## 5. Data Handling Procedures
- Classify new datasets before storage; label files and workspaces accordingly.
- When exporting data for troubleshooting, prefer pseudonymization (hash user IDs) and store in temporary, access-controlled locations.
- Define secure disposal procedures for temporary exports: deletion certified within 7 days.
- Document cross-border data transfer approvals if MFA logs contain EU/UK user data.

## 6. Compliance Sign-Off Checklist
- ✅ Confirm policies reviewed with Compliance/GRC representative.
- ✅ Register data stores (Log Analytics workspaces, storage accounts) in the data inventory/CMDB.
- ✅ Validate retention schedules configured and tested (including archival/restore).
- ✅ Verify access controls and DLP policies operational.
- ✅ Record residual risk items and mitigation plan.

## 7. Open Actions
- Identify Compliance owner to approve the classification and retention plan.
- Confirm whether legal requires additional consent for exporting MFA logs to third-party SIEMs.
- Draft a privacy impact assessment (PIA) summary referencing MFA telemetry handling for audit purposes.
