# Playbook MFA-PL-003 – Enforce MFA for Privileged Roles

| Field | Value |
|-------|-------|
| Playbook ID | MFA-PL-003 |
| Detection Source | `MFA-DET-003` MFA Disabled for Privileged Role |
| Owner | SecOps IAM Team |
| Response SLA | 24 hours |
| Review Cadence | Monthly |

## Purpose
Ensure privileged identities maintain compliant MFA posture by re-enabling enforcement, registering strong methods, and validating conditional access coverage. The playbook is designed for detections that flag privileged accounts lacking any active MFA method.

## Preconditions
- Analyst has Microsoft Graph connectivity (`Connect-MfaGraphDeviceCode`).
- Detection payload includes the user principal name, role context, and current MFA status.
- IAM change-management procedures allow scripted updates (or require manual approvals captured in tickets).

## High-Level Steps
1. **Validate Context** – Confirm Graph connectivity unless skipped with `-SkipGraphValidation`.
2. **Assess Role & Exemptions** – Identify privileged roles assigned to the user and check for approved exemptions.
3. **Remediate MFA Settings** – Re-enable MFA enforcement, add strong methods, or remove legacy exemptions.
4. **Confirm Conditional Access Coverage** – Ensure applicable policies include the account; suggest policy updates when gaps exist.
5. **Document Changes** – Update the incident/ticket with remediation evidence and schedule follow-up verification.

## Automation
Use `Invoke-MfaPlaybookEnforcePrivilegedRoleMfa` to orchestrate the remediation steps with verbose output, `-WhatIf` simulations, and optional skips for notifications or ticket updates.

```powershell
$detection = [pscustomobject]@{
    DetectionId = 'MFA-DET-003'
    UserPrincipalName = 'admin@example.com'
    PrivilegedRoles = @('Global Administrator')
}
Invoke-MfaPlaybookEnforcePrivilegedRoleMfa -Detection $detection -WhatIf -Verbose
```

## Manual Fallback
- Apply MFA policies manually in the Azure portal or via established IAM workflows if automation is blocked.
- Coordinate with governance teams when exemptions are requested; document approvals in the incident record.

## Success Criteria
- Privileged account is re-enrolled with compliant MFA factors.
- Conditional access policies and exemptions reviewed and updated as needed.
- Incident/ticket updated with remediation summary within SLA.

