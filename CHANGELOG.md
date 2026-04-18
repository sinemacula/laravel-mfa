# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/), and this project adheres
to [Semantic Versioning](https://semver.org/).

## [1.0.0] - 2026-04-16

Initial release of `sinemacula/laravel-mfa`.

### Added

- Driver-based MFA manager with four built-in factor drivers: TOTP, email code, SMS code, and backup
  codes.
- Pluggable driver API via `Mfa::extend()` for registering custom factor types against the
  `FactorDriver` contract.
- `RequireMfa` and `SkipMfa` route middleware, including step-up parameterisation (`mfa:N`) to gate
  sensitive actions behind a recent verification without tightening the global expiry.
- Structured `MfaRequiredException` and `MfaExpiredException` carrying masked `FactorSummary` payloads
  so consuming apps can render the available factors without leaking secrets.
- Polymorphic `Factor` Eloquent model with publishable migration, ULID primary key, and an `encrypted`
  cast on the secret column. Swappable via `config('mfa.factor.model')` / `mfa.factor.table`.
- `MfaPolicy` extension seam for organisation- or role-aware enforcement, with a `NullMfaPolicy`
  default.
- `MfaVerificationStore` extension seam, with `SessionMfaVerificationStore` as the default
  session-backed implementation.
- `SmsGateway` extension seam, with `NullSmsGateway` as the default that fails loud when SMS is used
  without a bound implementation. Includes a worked Twilio example in the README.
- TOTP provisioning URI helper for QR-code rendering during enrolment.
- Configurable code alphabet on the email and SMS drivers (numeric default; opt-in to Crockford
  base32, hex, or any custom set for ambiguity-resistant or voice-friendly delivery).
- HTTP-layer rate-limiting recipe in the README, layering Laravel's `RateLimiter` on top of the
  per-factor lockout to defend against distributed brute-force and lockout-window DoS.
- Lifecycle events: `MfaChallengeIssued`, `MfaVerified`, `MfaVerificationFailed`,
  `MfaFactorEnrolled`, and `MfaFactorDisabled`.
