# Integration Configuration – Ticketing & Notifications

MFA Check & Steer ships opinionated defaults for downstream ticketing and notification hooks so SecOps teams can capture decisions even before production integrations exist. Analysts can tune these behaviors without touching module code by supplying an `integrations.json` file that mirrors the schema outlined below.

> The module automatically loads configuration from `config/integrations.json` at import time. Set the `MfaIntegrationConfigurationPath` environment variable to point at an alternate file (for example in a secure share or deployment package) when you need environment-specific values.

## Default Layout

```jsonc
{
  "Ticketing": {
    "Provider": "Generic",
    "Endpoint": null,
    "DefaultAssignmentGroup": "SecOps-MFA",
    "Authorization": {
      "Type": "None",
      "TokenEnvVar": null,
      "UsernameEnvVar": null,
      "PasswordEnvVar": null
    },
    "FallbackPath": "tickets/outbox"
  },
  "Notifications": {
    "Provider": "Generic",
    "WebhookUrlEnvVar": null,
    "FallbackPath": "notifications/outbox"
  }
}
```

- **Ticketing** controls `Submit-MfaPlaybookTicket`.
  - `Provider` is an opaque label used for metadata and payload shaping (e.g., `ServiceNow`, `Jira`).
  - `Endpoint` sets the webhook/REST target. When `null`, the module writes payloads to disk instead of an HTTP POST.
  - `DefaultAssignmentGroup` seeds the payload with the queue analysts expect the incident to land in.
  - `Authorization` supports three modes:
    - `None` – no auth headers are added.
    - `Bearer` – read the token from the environment variable named in `TokenEnvVar` (process scope first, then machine scope).
    - `Basic` – build an Authorization header from `UsernameEnvVar` and `PasswordEnvVar`.
  - `FallbackPath` is a workspace-relative directory used when ticket submission cannot reach the endpoint (missing credentials, HTTP failure, or explicit file mode). The module creates the directory if it does not exist.
- **Notifications** controls `Send-MfaPlaybookNotification`.
  - `Provider` changes the payload shape (`Teams`/`Slack` produce `{ text = ... }`, other providers default to `{ message = ... }`).
  - `WebhookUrlEnvVar` resolves the target URL at runtime. When absent or empty, delivery falls back to file output.
  - `FallbackPath` mirrors the ticketing behavior but for notification payloads.

## Extending the Configuration

- Copy `config/integrations.json` and override the fields you need. Unspecified properties continue to inherit defaults.
- You can add custom properties under `Ticketing` or `Notifications` for downstream automation; they are exposed on the objects returned by `Get-MfaIntegrationConfig` so advanced scripts can read them.
- All nested objects are projected as `pscustomobject` instances, making property access easy in PowerShell (`(Get-MfaIntegrationConfig -Area Ticketing).Authorization.TokenEnvVar`).

### Environment Variables

- `MfaIntegrationConfigurationPath` – absolute or relative path to the JSON file that should override the repo default.
- Token or credential variables (e.g., `PLAYBOOK_TICKET_TOKEN`, `PLAYBOOK_NOTIFY_URL`) are free-form; choose names that meet your secret-management standards and reference them in the configuration file.
- Leave sensitive values out of source control. Point the config at environment variables managed by your secret store or deployment pipeline.

## Change Control Recommendations

1. Store a redacted sample in the repo (the default file) and keep production secrets in environment-specific copies.
2. Version integration files alongside infrastructure-as-code templates so ops can track when endpoints or auth models change.
3. After updating config values, run `Invoke-Pester -Path tests/MFACheckandSteer.Tests.ps1` to confirm ticketing/notification helpers still behave as expected.
4. Monitor the `tickets/outbox` and `notifications/outbox` folders during dry runs. Their presence usually indicates missing credentials or endpoint issues.

## Quick Start Checklist

- [ ] Decide which ticketing provider(s) to support and capture the required auth model.
- [ ] Create or update `config/integrations.json` (or drop-in override) with provider names, endpoints, assignment groups, and env var references.
- [ ] Populate the referenced environment variables in your automation host or CI runner.
- [ ] Validate by running a representative playbook command with `-WhatIf` plus `Invoke-MfaPlaybookOutputs` (or `Submit-MfaPlaybookTicket` / `Send-MfaPlaybookNotification`) to inspect the generated payloads.

With this structure in place, analysts can iterate on downstream workflows without waiting on code changes or module releases.
