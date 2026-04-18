# Per-Device Verification and Step-Up

## Purpose

This note documents how the package decides whether an identity has a currently-valid MFA verification, and how
consumers force a re-verification for sensitive actions without locking the user out globally. The behaviour is driven
by a single swappable seam — the `MfaVerificationStore` contract — plus the `RequireMfa` route middleware.

## Invariants

- Verification state lives behind `MfaVerificationStore`. The manager never writes timestamps to a fixed backend —
  every read and write goes through the bound implementation.
- The shipped default binding is `SessionMfaVerificationStore`, which persists the verification timestamp in the
  session. Session state is naturally per-device on any stateful auth stack (SessionGuard, Sanctum, any guard that
  regenerates session on login), so the default behaviour is per-device without the consumer doing anything.
- Stateless auth stacks (JWT, personal access tokens) are expected to rebind the store. The paired
  `sinemacula/laravel-authentication` stack binds a device-backed store; the `laravel-iam` parent package ships that
  binding — this repo does not depend on either.
- Session keys are scoped by identity class AND auth identifier. Two identities that share an id (`User#7` and
  `Admin#7`) living in the same session do NOT collide on a single slot — each has its own verification timestamp.
- `markVerified()` accepts an optional explicit `$at`. Passing one lets a paired-mode store stamp the persistence
  layer atomically with the verification event instead of trusting a subsequent `Carbon::now()` read. The shipped
  session store defaults to `now()` when `$at` is omitted.
- `MfaManager::hasExpired()` is the single source of truth for "does this request need fresh verification?". It
  treats `verifiedAt === null`, `window <= 0`, or a future-dated `verifiedAt` (clock skew, malicious write) as
  expired. It is deliberately fail-closed.
- The `RequireMfa` middleware is the gate. It throws `MfaRequiredException` when the identity has no factors or has
  never verified, and `MfaExpiredException` when a prior verification has aged past the window. Both exceptions
  carry `FactorSummary` payloads suitable for rendering a factor-picker UI.
- The middleware parameter syntax `mfa:N` overrides the configured window per-route-group without mutating global
  config. It is the step-up lever for actions that demand a more recent verification than the default. `mfa:0`
  requires re-verification on every request in that group.
- Skip-enforcement is explicit. A request carrying the `skip_mfa` request attribute (set by the shipped `SkipMfa`
  middleware on the verification endpoints themselves) bypasses `RequireMfa` entirely, avoiding circular enforcement.

## Success Path

- A user completes a verification. `MfaManager::verify()` calls `store->markVerified($identity)` through the bound
  implementation before dispatching `MfaVerified`. The default session store stamps the current Unix timestamp under
  `mfa.verified_at.<class>.<identifier>`.
- A subsequent request routes through `RequireMfa`. The middleware calls `Mfa::shouldUse()` (consumer-bound policy),
  `Mfa::isSetup()`, `Mfa::hasEverVerified()`, then `Mfa::hasExpired($maxAgeMinutes)`.
- `hasExpired()` resolves the bound store, reads `lastVerifiedAt($identity)`, and compares the elapsed time to
  either the route-parameter window (if present) or the `mfa.default_expiry` config value (minutes).
- For step-up: a controller route annotated with `mfa:5` runs the same middleware with a 5-minute window. The
  identity's prior verification is still valid globally but is rejected for this specific route group, prompting a
  fresh verification challenge.
- On logout or an administrative reset, the consumer calls `Mfa::forgetVerification()`, which delegates to
  `store->forget($identity)` to clear the stored timestamp so the next request hits `MfaRequiredException` rather
  than silently inheriting the old state.

## Failure / Edge Cases

- `hasExpired()` returns `true` when no identity resolves. A logged-out request is "expired" by construction.
- `hasExpired()` returns `true` when `verifiedAt` is in the future. The package never trusts a future-dated
  timestamp; clock skew and store-corruption both degrade to "re-verify", not "skip verification".
- A window of `0` (either from config or the route parameter) treats every prior verification as expired. The
  middleware correctly raises `MfaExpiredException` on every request against routes using that window.
- A non-numeric route parameter (`mfa:foo`) raises `InvalidArgumentException` the first time the covered route
  handles a request. Misconfigurations fail loud rather than silently using the default window.
- A negative `elapsed` (future `verifiedAt`) is explicitly handled: `hasExpired()` treats it as expired.
  `diffInMinutes(..., absolute: false)` is used intentionally so the sign is preserved.
- The `SessionMfaVerificationStore::key()` helper throws `UnsupportedIdentifierException` if the auth identifier is
  non-scalar. This is a programmer-configuration fail, not a silent identity collapse.
- If a consumer disables Laravel's session regeneration on login, a new identity could inherit the prior identity's
  verification slot. The shipped store documents that consumers in this configuration must call
  `Mfa::forgetVerification()` themselves on auth state change.
- Non-int values stored under the session key (e.g. tampered session or cache-migration debris) fall back to `null`
  from `lastVerifiedAt()`, which `hasExpired()` treats as "never verified" — fail-closed.

## Implementation Anchors

- `src/Contracts/MfaVerificationStore.php`: `markVerified($identity, ?$at)`, `lastVerifiedAt($identity)`,
  `forget($identity)`.
- `src/Stores/SessionMfaVerificationStore.php`: shipped default implementation, including the identity-class-scoped
  `key()` helper.
- `src/MfaManager.php`: `hasExpired()`, `markVerified()`, `forgetVerification()`, `finaliseVerification()` (writes
  through the store on successful verify).
- `src/Middleware/RequireMfa.php`: `handle()`, `parseMaxAgeMinutes()`, `resolveFactorSummaries()`.
- `src/Middleware/SkipMfa.php`: sets the `skip_mfa` request attribute for the verification endpoints.
- `src/Exceptions/MfaRequiredException.php`, `src/Exceptions/MfaExpiredException.php`.
- `config/mfa.php`: `default_expiry` (minutes).

## Authoritative Tests

- `tests/Unit/Stores/SessionMfaVerificationStoreTest.php`
  `testImplementsMfaVerificationStoreContract`
- `tests/Unit/Stores/SessionMfaVerificationStoreTest.php`
  `testMarkVerifiedWithoutTimestampStampsNow`
- `tests/Unit/Stores/SessionMfaVerificationStoreTest.php`
  `testMarkVerifiedWithExplicitTimestampStampsGivenTimestamp`
- `tests/Unit/Stores/SessionMfaVerificationStoreTest.php`
  `testKeysAreScopedByIdentityClass`
- `tests/Unit/Stores/SessionMfaVerificationStoreTest.php`
  `testKeysAreScopedPerIdentity`
- `tests/Unit/Stores/SessionMfaVerificationStoreTest.php`
  `testMarkVerifiedThrowsWhenIdentifierIsNotScalar`
- `tests/Unit/Stores/SessionMfaVerificationStoreTest.php`
  `testLastVerifiedAtReturnsNullWhenStoredValueIsNotInt`
- `tests/Unit/MfaManagerExpiryTest.php`
  `testHasExpiredReturnsTrueWhenNoIdentity`
- `tests/Unit/MfaManagerExpiryTest.php`
  `testHasExpiredReturnsTrueWhenNoPriorVerification`
- `tests/Unit/MfaManagerExpiryTest.php`
  `testHasExpiredUsesConfiguredDefaultExpiryWhenParameterOmitted`
- `tests/Unit/MfaManagerExpiryTest.php`
  `testHasExpiredReturnsTrueWhenExplicitExpiryIsZero`
- `tests/Unit/MfaManagerExpiryTest.php`
  `testHasExpiredReturnsTrueForFutureDatedVerification`
- `tests/Unit/MfaManagerExpiryTest.php`
  `testHasExpiredReturnsFalseAtExactWindowBoundary`
- `tests/Unit/MfaManagerExpiryTest.php`
  `testHasExpiredReturnsTrueOneMinuteAfterWindowBoundary`
- `tests/Unit/Middleware/RequireMfaTest.php`
  `testThrowsMfaRequiredWhenNotSetup`
- `tests/Unit/Middleware/RequireMfaTest.php`
  `testThrowsMfaRequiredWhenNeverVerified`
- `tests/Unit/Middleware/RequireMfaTest.php`
  `testThrowsMfaExpiredWhenVerificationExpired`
- `tests/Unit/Middleware/RequireMfaTest.php`
  `testPassesThroughWhenSkipMfaAttributeSet`

## Change Triggers

Update this note when any of the following change:

- the `MfaVerificationStore` contract (method set or signatures)
- the decision that the shipped session store scopes keys by identity class AND identifier
- the rule that `hasExpired()` treats null, zero-window, and future-dated verifications as expired
- the `mfa:N` route-parameter syntax or the strict-regex validation applied to it
- the two-exception payload shape (`MfaRequiredException` vs `MfaExpiredException`, both carrying
  `FactorSummary[]`)
- the `skip_mfa` request-attribute escape hatch used by the verification endpoints
- whether `markVerified()` continues to accept an explicit `$at` for atomic pairing with paired-mode stores
