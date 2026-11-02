# Testing Helpers

## Purpose

This note records what the public helpers in `Testing` promise an application's tests, why acting as a verified identity
is built the way it is, and which test helpers deliberately stay private to the package.

## Invariants

- The fakes keep what they are given. `FakeEmailSender::lastCodeTo()` reads the message's own field. `FakeSmsSender` has
  no such method, because it has no authoritative code, only rendered text, and now that the wording is customisable a
  digit heuristic could return a help line's phone number.
- `AuthenticatorApp` reads `CarbonImmutable::now()`, the driver's clock, so `Carbon::setTestNow()` is the frozen time.
  There is no `$at` parameter and no refusal of an unfrozen clock.
- `AuthenticatorApp` does not depend on PHPUnit. A factor that is not `totp` (`TotpParameters::fromFactor()` does not
  check the type), lacks parameters, or has a secret that does not decode to a non-empty key (`Base32::decode('')` gives
  `''`) is an `InvalidArgumentException` with no secret in its message.
- `actingAsVerified()` checks its arguments before any state changes, and reads the outcome back through the same
  `SessionFirstFactor::proofs()` and `RequirementCheck` the route gate uses.
- There is one table of further proofs and no branch on a level: the bound policy judges real evidence. Under the
  default policy, which caps at AAL2, AAL3 fails loudly naming `aal2`, while a custom policy can rate the
  hardware-bound, verified, phishing-resistant evidence `aal3`.
- The fixture is exact: the requirement's parts must all be met AND `evaluation->level` must equal the level asked for.
  With `meets()`, a test asking for AAL1 could get AAL2 and pass a route it meant to fail. It asks for additional
  verification as well, because the level alone reads AAL1 from the password when the email proof was rejected.
- `VerifiedSignIn` is stateless and resolves everything on each call. The trait depends on no base test case, since
  Testbench's does not extend Laravel's, and nothing in the package depends on a sibling package.

## Success Path

1. The arguments are checked: `UNCLASSIFIED` and a future `$at` are refused, and `$at` defaults to now.
2. The guard is `$guard ?? $auth->getDefaultDriver()` (never `SessionGuard::getName()`, which names a session key). A
   guard already holding this identity, by class and auth identifier, is not `setUser()`'d, so a contextual guard
   arranged by its own helper keeps its context. Then `shouldUse()`. On a model, `wasRecentlyCreated` becomes `false`,
   as `be()` does.
3. The application is the argument, else `ProofService::applicationFor($guardName)`.
4. `ProofStore::begin()` with a lower-case ULID, then `currentSession()`.
5. A password first factor is recorded at `$at`, unless the store already holds one, which is kept.
6. The further proof is recorded at `$at`, an additional factor for sign-in, under the identity's current verification
   generation, with synthetic references: nothing judges a reference against factor rows at read time.
7. The proofs are read back and evaluated. Any shortfall or excess is a `LogicException` in one format, naming what was
   requested, what was reached and what is unmet.

## Failure / Edge Cases

- A store whose `begin()` does nothing and that knows no session is a `LogicException`: it needs its session arranged.
- Such a store retaining further proofs is a `LogicException`, since the time cannot be honoured. The shipped store has
  just cleared, so this only bites a no-op `begin()`.
- A retained first factor later than `$at` needs no branch: the further proof does not count, and the read-back reports
  it.
- A resolver's first factor is not preserved. `SessionFirstFactor::proofs()` consults the resolver only when the store
  holds none, so two first factors cannot arise, and preserving it would make recipes fail on a declared `email` or
  `sms` first factor.
- The route's whole requirement is not checked, since an application may ask more than the fixture arranges.
- It dispatches no `Login` and no MFA event; `Authenticated` still fires from `setUser()`. It enrols no factor, and
  bypasses no inactivity check, re-enrolment obligation or stricter requirement.
- It needs the package's migrations, for the generation. Advancing the generation afterwards stops the proofs counting,
  as it should.
- `Store::start()` is `array_replace($attributes, $handlerData)`, so stored values win when a test carries a session
  cookie with its own `mfa.proofs`.
- The application given chooses where proofs go, not what the next request resolves.

Only `AuthenticatorApp` moved out of the package's own fixtures. `SignInProofs` deliberately builds wrong evidence, and
`ArrangesVerification` is tied to the package's own test identities and settings, so both stay there.

## Implementation Anchors

- `src/Testing/AuthenticatorApp.php`, `src/Testing/VerifiedSignIn.php`, `src/Testing/Concerns/InteractsWithMfa.php`.
- `src/Testing/FakeSmsSender.php`, `src/Testing/FakeEmailSender.php`, `src/Testing/FakeSenderBinding.php`.
- `src/Context/SessionFirstFactor.php`: `proofs()`; `src/Contracts/RequirementCheck.php`.

## Authoritative Tests

- `tests/Unit/Testing/AuthenticatorAppTest.php`: the published vectors, written out independently of the code; the real
  driver accepting a code once; each refusal, none showing the secret.
- `tests/Feature/Testing/ActingAsVerifiedTest.php`: through the real `web` group and `mfa:` routes: each level, the
  time, each refusal leaving nothing changed, AAL3 under the default and a custom policy, a second request, guards and
  applications kept apart, a store with a no-op `begin()`, recording guards, the generation, the events.
- `tests/Unit/Testing/FakeSmsSenderTest.php`, `tests/Unit/Testing/FakeEmailSenderTest.php`.

## Change Triggers

Revisit this note when the proofs a level is made of change, when the gate reads a session's proofs by another path,
when a store gains a way to record a past time, or when a test helper in `tests/Fixtures` starts being useful to an
application.
