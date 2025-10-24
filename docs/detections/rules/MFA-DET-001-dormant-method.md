# Detection Spec — MFA-DET-001 Dormant MFA Method

| Field | Value |
|-------|-------|
| ID | MFA-DET-001 |
| Name | Dormant MFA Method |
| Severity | Medium |
| Owner | SecOps Detection Engineering |
| Last Review | 2025-10-23 |

## Description
Identify user accounts whose default MFA method has not been updated or used in an extended period (default 90 days). Dormant methods increase the risk that outdated phone numbers or dormant authenticator apps remain active.

## Data Requirements
- Canonical registration dataset produced by `Get-MfaEntraRegistration -Normalize`.
- Optional future input: method usage telemetry once available.

## Logic (Pseudocode)
```
param(
    [datetime] $Cutoff = (Get-Date).AddDays(-90)
)

$records = Get-MfaEntraRegistration -Normalize
$records
    | Where-Object { $_.IsDefault -eq $true }
    | Where-Object { $_.LastUpdatedDateTime -lt $Cutoff -or -not $_.LastUpdatedDateTime }
    | Select UserPrincipalName, MethodType, LastUpdatedDateTime
```

## Tunable Parameters
- `DormantDays` (default 90) — number of days since `LastUpdatedDateTime`.

## Considerations
- Some method types (e.g., FIDO2 keys) rarely rotate; tune severity or exclusions for approved devices.
- Tenants without `LastUpdatedDateTime` values should default to manual review.

## Framework Alignment
- **MITRE ATT&CK**: `T1078` (Valid Accounts)
- **NIST CSF**: `PR.AC-1`, `PR.AC-6`

## Reporting Tags
- `Configuration`
- `MFA`
- `DormantMethod`
- `Risk-Medium`

## Response Mapping
- Review with user to confirm method is still valid.
- If method is obsolete, enforce re-registration via playbook `MFA-PL-001` (`Invoke-MfaPlaybookResetDormantMethod`) and capture evidence in the ticket.

## Testing
- Create sample registration entries in `data/samples/` where `LastUpdatedDateTime` is older than the threshold and verify detection triggers.
