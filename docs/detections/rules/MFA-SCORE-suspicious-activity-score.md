# Detection Spec - MFA-SCORE Suspicious Activity Score

| Field | Value |
|-------|-------|
| ID | MFA-SCORE |
| Name | Suspicious Activity Score |
| Severity | Medium–Critical (dynamic) |
| Owner | SecOps Detection Engineering |
| Last Review | 2025-10-24 |

## Description
Correlates multiple weak signals (impossible travel, repeated failures, unusual devices, recent weak-factor changes) across a 24‑hour window and emits a composite score per identity. The score ranges from 0–100 and is mapped to severity bands (Medium ≥25, High ≥50, Critical ≥75). The detection is intentionally opinionated so analysts receive a single “hot list” instead of chasing individual noisy alerts.

## Data Requirements
- Canonical Microsoft Entra sign-ins (`Get-MfaEntraSignIn -Normalize`).
- Canonical MFA registration dataset (`Get-MfaEntraRegistration -Normalize`). Used to check for recent default-method changes and weak factors.
- (Optional) Additional identity providers can be fused later if they preserve the same `Indicators` schema.

## Logic (Summary)
1. Gather normalized sign-ins for the lookback window (configurable, default 24h).
2. Build per-user aggregates:
   - **RepeatedFailures** – ≥3 failures within a 15‑minute eye (configurable).
   - **ImpossibleTravel** – successes from distant geos within 2 hours.
   - **UnusualDevice** – first-time device/app combos.
   - **HighRiskFactorChange** – default method switched to weak factor within the past 7 days.
3. Assign weights to each indicator (40/20/15/25 respectively), sum per identity, then emit the score with indicator metadata.

## Investigation Workflow
1. **Confirm raw evidence.** Run:
   ```powershell
   $end   = Get-Date
   $start = $end.AddHours(-24)
   Get-MfaEntraSignIn -Normalize -UserPrincipalName <user> -StartTime $start -EndTime $end |
       Select-Object CreatedDateTime, AppDisplayName, IpAddress, Result, ResultFailureReason, LocationCity, LocationCountryOrRegion |
       Format-Table -AutoSize
   ```
   This surfaces the exact sign-ins that contributed to `RepeatedFailures` / `ImpossibleTravel` indicators.
2. **Check account state.** Many “ghost user” detections turn out to be dormant or former employees whose usernames are still valid. Use `Get-MgUser -Filter "userPrincipalName eq '<user>'"` (or the Azure portal) to confirm `accountEnabled`, licensing, and group memberships.
3. **Containment.**
   - If the account is obsolete, disable sign-in (`Update-MgUser -AccountEnabled:$false`), strip licenses, and remove group memberships.
   - If the account is still active, follow MFA-PL-004 (triage) and escalate to MFA-PL-002 for containment if additional signals confirm compromise.

## Real-World Example (Tenant Report 2025-10-24)
- **Identity:** `matthew.lush@fusioncomputing.ca` (former employee).
- **Evidence:** Nine password-spray attempts (error 50126) within the last 24 hours coming from Azure CLI/Exchange PowerShell clients across Luxembourg, the United States, and the United Kingdom. Example log (10/24/2025 18:03:50Z) shows Azure CLI from `2605:6400:c077:cd6b:43cd:78dd:9800:1c94` failing due to invalid credentials.
- **Why MFA-SCORE fired:** The `RepeatedFailures` indicator crossed the default threshold (≥3 failures/15 min) multiple times, giving the identity a score of 80 (Critical). Indicators listed in the report: `RepeatedFailures`, `UnusualDevice` (Azure CLI / Exchange REST for a deprovisioned user), and `HighRiskFactorChange` (default method still weak SMS).
- **Action:** Disable the legacy account, move associated mailbox to litigation/archive if necessary, and document the closure in the ticket produced by `Invoke-MfaTenantReport`. Re-enable only if HR confirms the user is returning.

## Tuning
- `config/detections.json` → `MFA-SCORE` block controls thresholds (e.g., set `FailureThreshold` higher if your tenant has noisy automation accounts).
- Consider excluding sanctioned service principals via the future `IgnoredUserPrincipalNames` list if automation intentionally replays failed logins for monitoring.

## Reporting Tags
- `Detection`
- `CompositeSignal`
- `SuspiciousActivity`

## Response Mapping
- Primary playbook: `MFA-PL-004` (triage suspicious scores).
- Escalation: `MFA-PL-002` (contain high-risk sign-in) when root cause proves malicious.
