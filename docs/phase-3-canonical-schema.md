# Phase 3.2 — Canonical MFA Event Schema

To support consistent analytics, alerting, and storage, the MFA Check & Steer module flattens Microsoft Graph responses into a canonical schema. The schema covers two record types:

1. `SignIn` — Authentication attempts sourced from `/auditLogs/signIns`.
2. `Registration` — User authentication method registrations sourced from `/users/{id}/authentication/methods`.

The schema is intentionally minimal and focused on the fields most relevant to SecOps. Additional attributes can be layered on in later iterations without breaking existing consumers.

## 1. Canonical Sign-In Record (RecordType = `SignIn`)
| Field | Type | Description | Source |
|-------|------|-------------|--------|
| `RecordType` | string | Literal value `SignIn`. | Derived |
| `Id` | string | Graph sign-in identifier. | `id` |
| `TenantId` | string | Azure AD tenant ID. | `userTenantId` (Graph) |
| `CreatedDateTime` | datetime | UTC timestamp of the authentication attempt. | `createdDateTime` |
| `UserId` | string | Object ID of the user. | `userId` |
| `UserPrincipalName` | string | UPN of the authenticating user. | `userPrincipalName` |
| `UserDisplayName` | string | Display name of the user. | `userDisplayName` |
| `AppDisplayName` | string | Application name. | `appDisplayName` |
| `AppId` | string | Application (client) ID. | `appId` |
| `IpAddress` | string | IP address of the attempt. | `ipAddress` |
| `LocationCity` | string | Geographic city. | `location.city` |
| `LocationState` | string | Geographic state / region. | `location.state` |
| `LocationCountryOrRegion` | string | Geographic country/region. | `location.countryOrRegion` |
| `IsInteractive` | bool | Indicates interactive vs. non-interactive sign-in. | `isInteractive` |
| `AuthenticationRequirement` | string | Requirement evaluated (e.g., `mfa`). | `authenticationRequirement` |
| `AuthenticationRequirementPolicies` | string | Semicolon-separated list of Conditional Access policies evaluated. | `authenticationRequirementPolicies` (joined) |
| `AuthenticationMethods` | string | Semicolon-separated list of authentication methods attempted. | `authenticationDetails[].authenticationMethod` |
| `ConditionalAccessStatus` | string | Result of Conditional Access evaluation. | `conditionalAccessStatus` |
| `RiskDetail` | string | Reason for risk state. | `riskDetail` |
| `RiskLevelAggregate` | string | Aggregated risk level. | `riskLevelAggregated` |
| `RiskState` | string | Risk state assigned by Identity Protection. | `riskState` |
| `CorrelationId` | string | Correlation ID for cross-service tracing. | `correlationId` |
| `Result` | string | `Success` when `status.errorCode` is `0`; otherwise `Failure`. | Derived from `status.*` |
| `ResultErrorCode` | int | Raw error code. | `status.errorCode` |
| `ResultFailureReason` | string | Failure reason text. | `status.failureReason` |
| `ResultAdditionalDetails` | string | Additional status details. | `status.additionalDetails` |

## 2. Canonical Registration Record (RecordType = `Registration`)
| Field | Type | Description | Source |
|-------|------|-------------|--------|
| `RecordType` | string | Literal value `Registration`. | Derived |
| `UserPrincipalName` | string | User principal name provided to the cmdlet. | Parameter |
| `UserId` | string | Authentication method's underlying `userId` (if available). | `userId` or parameter |
| `MethodId` | string | Graph method identifier. | `id` |
| `MethodType` | string | Short method type (e.g., `phoneAuthenticationMethod`, `fido2AuthenticationMethod`). | `@odata.type` (parsed) |
| `DisplayName` | string | Friendly name/device label when present. | Property or `displayName` |
| `IsDefault` | bool | Indicates default method (if exposed by Graph). | `isDefault` |
| `IsUsable` | bool? | Indicates if method is enabled/usable. | `isUsable`, `isEnabled` |
| `PhoneNumber` | string | Phone number for phone/SMS methods. | `phoneNumber` |
| `PhoneType` | string | Phone type (mobile/alternate/office). | `phoneType` |
| `KeyDeviceId` | string | Device ID for FIDO2/Authenticator methods. | `deviceId`, `keyId` |
| `CreatedDateTime` | datetime? | Creation timestamp when exposed. | `createdDateTime` |
| `LastUpdatedDateTime` | datetime? | Last updated timestamp when exposed. | `lastUpdatedDateTime` |
| `AdditionalData` | hashtable | Catch-all for other method-specific attributes preserved for advanced use. | Remaining `AdditionalProperties` |

## 3. Implementation Notes
- Canonical conversion is opt-in via the `-Normalize` switch on `Get-MfaEntraSignIn` and `Get-MfaEntraRegistration`. The original Graph objects remain accessible when raw data is preferred.
- Unknown or missing values are set to `$null` (PowerShell `null`) to simplify downstream filtering.
- Arrays are flattened using semicolon-delimited strings unless a future consumer requires structured collections.
- Remaining `AdditionalProperties` are preserved in `AdditionalData` for registration records to ensure no data is lost.

## 4. Future Enhancements
- Extend the schema with geolocation metadata (latitude/longitude) when Conditional Access exports are enabled.
- Add normalization for Identity Protection risk detection details once those connectors are implemented.
- Provide JSON schema definitions and validation tests for consumers outside PowerShell.
- Optionally emit strongly-typed .NET classes if performance or serialization needs increase.
