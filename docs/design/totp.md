# TOTP

## Purpose

This note records how the TOTP driver makes and checks time-based one-time passwords (RFC 6238) for authenticator apps:
the secret and parameters a factor is enrolled with, how a code is checked against the window, and why a time step is
accepted at most once per factor, also when two requests race with the same code. The package computes the codes
itself over `hash_hmac`; it depends on no TOTP library, so there is none to be missing when it boots.

## Invariants

- A new enrolment's secret is `random_bytes()` as long as its algorithm's output, which RFC 6238 recommends for the key:
  20 bytes (160 bits) for SHA-1, 32 for SHA-256 and 64 for SHA-512, never under the 160 bits that exceed RFC 4226's
  128-bit minimum. It is handed over in Base32 (RFC 4648, upper case, unpadded), stored encrypted by the factor model's
  cast, and never logged or put in an exception.
- A factor keeps the algorithm, digits and period it was enrolled with (`totp_algorithm`, `totp_digits`,
  `totp_period`), taken from `mfa.totp` when its enrolment starts, so it works the same way in every application and
  after the configuration changes. The bounds are those of the configuration: `sha1`, `sha256` or `sha512`, 6 to 8
  digits, a period of 15 to 120 seconds. A factor holding no parameters, or parameters out of bounds, verifies nothing;
  it never falls back to the configured ones.
- A code is the HOTP value (RFC 4226 §5.3) of the time step, `floor(unix time / period)`: the HMAC of the step as an
  8-byte big-endian counter, dynamically truncated to 31 bits, reduced to the factor's digits and zero-padded.
- A submitted code is compared with the code of every step of the window, each with `hash_equals()`. The window is the
  `totp_window` of the application a bound `Contracts\ApplicationResolver` names for the current request, or
  `mfa.totp.window` when the application sets none, no resolver is bound or there is no request (default 1, at most 3).
  No comparison is skipped when an earlier one matches, and a malformed code is compared like any other, so the work
  does not depend on which step matches or whether one does. The latest matching step is the one accepted. The window
  is read from the configuration and the request on every call, so a driver built once serves each application with
  its own, and nothing widens it, failures included; the package does not resynchronise (RFC 6238 §6).
- A time step is single-use per factor (RFC 6238 §5.2). A matching code is accepted only when
  `EloquentFactor::storeAcceptedStep()` records its step, and it records it only when it is later than
  `last_accepted_step`: one compare-and-set, `UPDATE ... SET last_accepted_step = :step WHERE id = :id AND
  (last_accepted_step IS NULL OR last_accepted_step < :step)`, accepted when it changed the row. The database applies
  the condition to the row as committed, under the row's lock, so the check and the record are one atomic step and a
  request whose copy of the factor is stale cannot pass. Inside a transaction on the storage connection, such as
  `FactorStateTransaction`, it is part of that transaction and is undone with it: a verification flow that records the
  outcome in the same transaction leaves the step unused when that fails.
- Confirming a pending factor checks its first code the same way, so the confirming code's step is recorded and the
  code is refused at the next verification.
- The recorded step is kept as the model attribute's original value, so a later `persist()` of the same copy never
  writes it back over a later step another request recorded.
- A factor that implements only the `Factor` read surface has nowhere to record a step, so it cannot be held to single
  use: the driver computes the window and then refuses it. A custom model implementing `EloquentFactor` without
  `ActsAsFactor` must make `storeAcceptedStep()` the same atomic compare-and-set.

## Success Path

- Enrolment: `TotpDriver::startEnrollment($factor)` reads the parameters `mfa.totp` sets for new enrolments, stamps
  them on an Eloquent factor with `last_accepted_step` cleared, and returns a new secret. The caller stores the secret
  on the factor, shows it once with `provisioningUri($factor, $issuer, $accountName, $secret)`, and confirms the factor
  with the first code the app shows through `confirm()`, which records its step.
- The provisioning URI is the `otpauth://` key URI format: the label `issuer:account`, each part percent-encoded once,
  and the query `secret`, `issuer`, `algorithm` (upper case), `digits` and `period`, encoded per RFC 3986.
- Verification: `verify()` reads the factor's parameters and decodes its secret, computes the step of every moment of
  the window and compares each code, then records the matched step through `storeAcceptedStep()`. The verification
  service then records the outcome on the factor as for any type.

## Failure / Edge Cases

- No secret, an empty secret or one that is not Base32, no parameters or parameters out of bounds: refused before the
  window is computed, as nothing secret depends on it.
- The same code twice, or a code for a step at or before the last accepted one, though still in the window: the
  compare-and-set changes no row and the code is refused. A replay is reported as an invalid code and counted as a
  failed attempt.
- Two requests with the same code: both match, both issue the compare-and-set, and the database serialises them on the
  row; the second waits for the first to commit, then finds the step recorded and changes nothing. On MySQL this holds
  although the second request's transaction read the factor from a snapshot taken before the first committed, because an
  `UPDATE` reads the row as committed.
- A factor not yet stored has no row another request can see, so it compares with its own attribute, and the recorded
  step is stored with it.
- An application that sets no `totp_window`, or one nobody configured, gets `mfa.totp.window`; so does a request when
  no `ApplicationResolver` is bound, which is the case until an authentication layer or the application binds one.
- The driver opens no transaction of its own. The compare-and-set needs none to be atomic, and the transaction that
  also holds the identity's lock and records the outcome belongs to the verification flow: the attempt service calls
  the driver inside its `FactorStateTransaction`, on the factor as stored under the lock, so the recorded step commits
  with the attempt's count and is undone with it (see [Attempts and Lockout](attempts-and-lockout.md)).

## Implementation Anchors

- `src/Drivers/TotpDriver.php`: `startEnrollment()`, `confirm()`, `verify()`, `matchedStep()`, `application()`,
  `parameters()`, `provisioningUri()`.
- `src/Drivers/TotpParameters.php`: the bounds, `fromFactor()`, `secretLength()`, `stepAt()`, `code()`.
- `src/Drivers/Base32.php`: `encode()`, `decode()`.
- `src/Drivers/TotpSettings.php`: `parameters()`, `window()`, `windowFor()`.
- `src/Applications/ApplicationSettings.php`: `totpWindow()`, the application's own window.
- `src/Contracts/EloquentFactor.php` and `src/Concerns/ActsAsFactor.php`: `storeAcceptedStep()`.
- `src/Drivers/DriverBindings.php`: `totp()`, the driver built over `TotpSettings` and the container.

## Authoritative Tests

- `tests/Unit/Drivers/TotpParametersTest.php`
  `testMatchesTheRfc6238Vector`
- `tests/Unit/Drivers/TotpDriverTest.php`
  `testVerifiesTheRfc6238Vector`
- `tests/Unit/Drivers/TotpDriverTest.php`
  `testTheDefaultWindowAcceptsOneStepEitherSideOnly`
- `tests/Unit/Drivers/TotpDriverTest.php`
  `testTheWindowIsTheRequestedApplicationsOwn`
- `tests/Unit/Drivers/TotpDriverTest.php`
  `testWithoutARequestThePackageWideWindowApplies`
- `tests/Unit/Drivers/TotpDriverTest.php`
  `testTheWindowNeverWidensAfterFailures`
- `tests/Unit/Drivers/TotpDriverTest.php`
  `testRefusesTheSameStepTwice`
- `tests/Unit/Drivers/TotpDriverTest.php`
  `testRefusesAnEarlierStepOnceALaterOneIsAccepted`
- `tests/Unit/Drivers/TotpDriverTest.php`
  `testTheConfirmingCodeIsRefusedAtTheNextVerification`
- `tests/Unit/Drivers/TotpDriverTest.php`
  `testRefusesAFactorThatCannotRecordAStep`
- `tests/Unit/Drivers/TotpDriverTest.php`
  `testANewSecretIsAsLongAsTheAlgorithmOutput`
- `tests/Unit/Drivers/TotpDriverTest.php`
  `testAnEnrolledFactorKeepsItsParameters`
- `tests/Unit/Drivers/TotpDriverTest.php`
  `testTheProvisioningUriCarriesTheLabelSecretAndParameters`
- `tests/Unit/Drivers/Base32Test.php`
- `tests/Unit/Concerns/ActsAsFactorStoreAcceptedStepTest.php`
  `testAStaleCopyCannotRecordAStepAnotherCopyRecorded`
- `tests/Unit/Concerns/ActsAsFactorStoreAcceptedStepTest.php`
  `testPersistingAfterwardsKeepsALaterStepAnotherCopyRecorded`
- `tests/Unit/Concerns/ActsAsFactorStoreAcceptedStepTest.php`
  `testAStepRecordedInsideATransactionRollsBackWithIt`
- `tests/Integration/Database/TotpReplayRaceTest.php`
  `testOnlyOneOfTwoRequestsWithTheSameCodePasses`
- `tests/Integration/Database/TotpReplayRaceTest.php`
  `testOfTwoOverlappingRequestsWithTheSameCodeOnlyOnePasses`
- `tests/Feature/TotpLifecycleTest.php`
  `testTheConfirmingCodeIsRefusedAtTheNextVerification`

## Change Triggers

Update this note when any of the following change:

- the secret's length or source, or its encoding
- the parameters a factor stores, their bounds, or the rule that a factor never takes the configured ones
- the code computation, or the comparison of every step of the window
- the window's source or bounds, or anything that would widen it
- the compare-and-set that records an accepted step, or where it runs
- the provisioning URI's format
