# Phase 3.3 — Sample Datasets & Replay Script

To support local development and automated tests without hitting live tenants, the repository includes synthetic sample data and a helper script that replays canonical MFA events.

## Provided Assets
| File | Description |
|------|-------------|
| `data/samples/entra-signins-sample.json` | Two canonical sign-in records demonstrating success/failure scenarios. |
| `data/samples/entra-registrations-sample.json` | Canonical registration records covering phone and FIDO2 methods. |
| `scripts/replay-samples.ps1` | Loads the sample JSON and prints a summary or emits raw JSON for pipelines. |

All samples are fabricated; IDs, IP addresses, and timestamps are safe for public use.

## Usage Examples
```powershell
# View both datasets in table form
pwsh scripts/replay-samples.ps1

# Emit only sign-ins as JSON for tests or Power BI load
pwsh scripts/replay-samples.ps1 -Dataset SignIn -AsJson | Out-File signins.json

# Pipe registrations into custom processing
pwsh scripts/replay-samples.ps1 -Dataset Registration -AsJson | ConvertFrom-Json | ForEach-Object {
    "$($_.UserPrincipalName) => $($_.MethodType)"
}
```

## Integration Notes
- The sample JSON already matches the canonical schema defined in `docs/phase-3-canonical-schema.md`. They can be imported directly into analytics tooling or used as fixtures in future automated tests.
- When extending the schema, remember to update these samples so documentation and replay coverage stay aligned.
- Add additional synthetic scenarios (e.g., service principal sign-ins, disabled methods) in new branch-specific files, and update the replay script to surface selection options.
