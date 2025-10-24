# Detection Spec - MFA-DET-003 Privileged Role Without MFA

| Field | Value |
|-------|-------|
| ID | MFA-DET-003 |
| Name | Privileged Role Without MFA |
| Severity | Critical |
| Owner | SecOps Detection Engineering |
| Last Review | 2025-10-24 |

## Description
Identify privileged identities (Global Administrator, Privileged Role Administrator, etc.) that lack compliant MFA coverage. The detection combines role assignment data with MFA registration status and exemption flags to surface high-risk accounts.

## Data Requirements
- Privileged role assignments for users (Graph endpoint `/roleManagement/directory/roleAssignments`).
- Canonical registration dataset from `Get-MfaEntraRegistration -Normalize`.
- Optional: Conditional access policy membership data to validate enforcement coverage (future enhancement).

## Logic (Pseudocode)
```
param(
    [string[]] $PrivilegedRoleIds,
    [psobject[]] $RoleAssignments,
    [psobject[]] $RegistrationData
)

$privilegedUsers = $RoleAssignments |
    Where-Object { $_.RoleDefinitionId -in $PrivilegedRoleIds } |
    Select-Object -ExpandProperty PrincipalId -Unique

foreach ($user in $privilegedUsers) {
    $registrations = $RegistrationData | Where-Object { $_.UserId -eq $user -and $_.IsUsable }
    if (-not $registrations) {
        Emit detection (Severity = Critical)
    }
}
```

## Tunable Parameters
- `PrivilegedRoles` - Role definition IDs considered privileged (default: Global Administrator, Privileged Role Administrator, Security Administrator, Conditional Access Administrator).
- `RequireStrongMethods` (future) - Require at least one strong method type (FIDO2, CA policy compliance).

## Considerations
- Break-glass accounts may be intentionally exempt; ensure playbook guidance documents approval workflow.
- Some organizations maintain just-in-time role assignment. Consider integrating with PIM to ignore expired assignments once available.
- Include conditional access checks in future iterations to ensure policies enforce MFA.

## Framework Alignment
- **MITRE ATT&CK**: `T1078` (Valid Accounts), `T1098` (Account Manipulation)
- **NIST CSF**: `PR.AC-4`, `PR.IP-1`

## Reporting Tags
- `Configuration`
- `PrivilegedRole`
- `Risk-Critical`

## Response Mapping
- Execute playbook `MFA-PL-003` (`Invoke-MfaPlaybookEnforcePrivilegedRoleMfa`) to re-enable MFA enforcement, validate CA coverage, and document remediation.

## Testing
- Create synthetic role assignment data where a privileged account lacks registration entries and confirm detection triggers.
- Include negative case where sufficient MFA methods exist to ensure no detection is emitted.

