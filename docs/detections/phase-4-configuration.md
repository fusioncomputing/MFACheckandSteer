# Phase 4.5 - Detection Configuration & Tuning

Roadmap task **4.5** introduces structured configuration so SecOps teams can tune detection thresholds and scoring parameters without editing code. The goal is to preserve sensible defaults while exposing guardrails and documentation for safe customization.

## Objectives
- Provide a central configuration file (`config/detections.json`) that defines environment-specific overrides.
- Offer PowerShell helpers for retrieving and validating configuration data.
- Respect override values inside detection functions while still allowing ad-hoc parameter adjustments via cmdlet arguments.
- Document recommended ranges, change control guidance, and rollback procedures.

## Configuration Model

```jsonc
{
  "MFA-DET-001": {
    "DormantDays": 90
  },
  "MFA-DET-002": {
    "ObservationHours": 24,
    "RiskDetailExclusions": [
      "none",
      "unknownFutureValue",
      ""
    ]
  },
  "MFA-DET-003": {
    "PrivilegedRoleIds": [
      "62e90394-69f5-4237-9190-012177145e10",
      "e8611ab8-c189-46e8-94e1-60213ab1f814"
      // Additional IDs omitted for brevity
    ]
  },
  "MFA-DET-004": {
    "ObservationHours": 24,
    "FailureThreshold": 3,
    "FailureWindowMinutes": 15
  },
  "MFA-DET-005": {
    "ObservationHours": 24,
    "TravelWindowMinutes": 120,
    "RequireMfaRequirement": true,
    "RequireSuccess": true
  },
  "MFA-SCORE": {
    "ObservationHours": 24,
    "FailureThreshold": 3,
    "FailureWindowMinutes": 30,
    "TravelWindowMinutes": 120,
    "RecentRegistrationDays": 7
  }
}
```

- Keys correspond to detection or scoring identifiers.
- Values map to parameter names consumed by the module functions. Missing values fall back to code defaults.
- `RiskDetailExclusions` illustrates array support when overriding lists.

## Usage Pattern
1. Update `config/detections.json` with desired overrides.
2. Use `Get-MfaDetectionConfiguration` to inspect the effective settings (merged defaults + overrides).
3. Run detections; overrides apply automatically unless explicit parameters are provided at call time.
4. Include configuration diff in change-management artifacts for traceability.

> Tip: set the `MfaDetectionConfigurationPath` environment variable to point the module at an alternate JSON file (useful for tests, sandboxes, or per-tenant baselines).

## Guardrails
- The module validates numeric ranges (e.g., minimum hours, positive thresholds) and warns when overrides fall outside recommended bounds.
- Overrides are opt-in per parameter; removing an entry reverts to the baked-in default.
- Version control the configuration file to track history and enable rollback.

## Documentation & Training
- Update `README.md` and `docs/detections/detection-strategy.md` with configuration references.
- Provide example change workflows (e.g., lowering `FailureThreshold` temporarily during heightened risk).
- Encourage SecOps to review configuration changes during cadence meetings established in Phase 1.

## Next Steps
1. Extend configuration coverage as new detections land (e.g., service-account coverage in later phases) and document recommended ranges alongside defaults.
2. Consider per-tenant configuration files or environment-specific overlays when multi-tenant support is added.
3. Surface configuration values in future reporting dashboards (Phase 6) to improve transparency.
