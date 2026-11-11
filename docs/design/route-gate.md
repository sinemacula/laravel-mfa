# Route Gate

## Purpose

This note records how the `mfa` route middleware decides a request, who it refuses, how a route is exempted, what its
exception carries, what the authentication context contributes, and why what a completion returns can never reach a
response if the commit fails.

## Invariants

- The gate judges the whole structured requirement against the session's proofs. Bare `mfa` is exactly the composed
  requirement (`RequirementService::requirementFor()`), with nothing implicit added: `never` adds nothing, and the
  identity, tenant and re-enrolment parts still apply. A route's level is composed into it with
  `Requirement::strictest()`.
- A served caller passes only when active, when the bound `RequirementCheck` finds its proofs
  (`SessionFirstFactor::proofs()`) meet the requirement, and, when the route names an operation, when
  `RequirementService::isFresh()` says so. The same read `SessionReevaluation` and the default gate use. The check
  always runs, with no shortcut for an empty requirement, so there is one path.
- An operation is judged only by the bound gate. The level or composed requirement is never passed in, since
  `OperationRequirements::callerRequirement()` refuses a part with no maximum age. A level has no maximum age.
- Whoever the package does not serve is refused, under `never` too, since that setting controls the requirement and not
  who is served: a pending session, a guest, a non-MFA identity, a machine and an inactive identity. A pending request
  is never answered from the guard's user, also with an active credential beside it. No gate is asked for an unserved
  caller, so its exception carries an operation's name and not its requirement.
- Parameters are parsed strictly and first, also on an exempt route: only `level` and `operation`, each once, each with
  a value, with one `=`. A well-formed operation with no requirement is not a misconfiguration; it raises the exception.
- The exempt marker is read from the route's resolved middleware (`Router::gatherRouteMiddleware()`), not a request
  attribute, which would depend on execution order: `mfa` in a group runs before a marker on the route. Resolved
  metadata expands aliases and groups and applies exclusions, and cannot be spoofed. The marker takes no parameters,
  which avoids the difference between Laravel 12 and 13 in how exclusions treat parameterised classes. It lifts every
  `mfa` form and grants nothing.
- The gate only reads. It never calls `SessionTransition`, so a GET never revokes credentials and a stale operation is a
  step-up. `SessionReevaluation` owns transitions, as part of the change that causes them, and
  `MiddlewareSessionTransition` stays a no-op because the middleware is the gate.
- The exception's requirement is the whole effective one, as `SessionReevaluation` reports it, not what is left of it:
  `Evaluation::$unmet` cannot cover a bound gate's boolean. It sets no `WWW-Authenticate`, since the package also serves
  cookie guards. `HttpException` is on Laravel's don't-report list and `FactorSummary` is masked, so nothing secret
  reaches a log.
- `AuthenticationContextContributor` is stateless, with exactly its eight keys always. `accepted` means the
  additional-verification requirement is met, including by a qualifying multi-factor first factor, and
  `Evaluation::$accepted` is untouched: a user-verifying passkey first factor alone has that field `false` and
  `multifactor` `true` while `provides()` meets the part, so reading the field literally would let the gate admit a
  session a policy "only with MFA" refuses. One evaluation serves `accepted`, `multifactor`, `level` and
  `phishing_resistant`.
- Evidence is a probe: each additional factor or recovery code for which `check(Requirement::none(), $firstFactor,
  $proof)` is accepted, as `ProofAcceptance::evaluate()` asks, since session and time filters do not mean a proof counts
  (a shared channel is rejected too) and `RequirementCheck` exposes no contributing proofs. It is exact under the
  default policy. A bound check may accept a pair yet refuse the set, so these fields are accepted recorded evidence,
  not what a policy selected.
- A `VerificationResult` or `EnrollmentConfirmation` exists for its caller only after the package's outermost commit.
  `accept()` hands over and calls `withCompletion()` inside `FactorStateTransaction`'s `transaction()`; `settled()`
  catches only `SignInChangedException` and `RefusedUnderLockException`, `AttemptService::throttled()` rethrows, and the
  outer `$settled` is assigned only after `transaction()` returns. So a commit failure propagates, and what a completion
  returned, with its tokens and cookie, reaches no response. A refusal after hand-over returns a failed result whose
  `completion()` is `null`.

## Success Path

1. A request reaches `mfa`, after authentication (`HttpBindings::boot()` places it straight after
   `AuthenticatesRequests`).
2. The parameters are parsed, and the route's marker is looked for.
3. The bound pending resolver is asked. With no pending session and a served caller, the requirement is composed, the
   proofs are judged and any operation goes to the bound gate.
4. The request goes on.

## Failure / Edge Cases

- A shortfall throws `InsufficientAuthenticationException` with the strictest of the requirement and the gate's
  requirement for the operation (`freshnessRequirement()`, whose name is non-nullable, hence the guard), the session's
  offers and whether a factor is confirmed. One query, on the failure path only. `Requirements\StepUpRefusal` builds it,
  for the gate and for `Mfa::stepUpRefusal()` alike, taking the requirement as given.
- An invalid pending credential makes the resolver throw. That propagates: it is not disguised as a refusal.
- An inactive identity, as the bound `ActiveStateResolver` says, is short-circuited and no gate judges it, though
  `freshnessRequirement()` is read for the exception.
- With no matched route nothing is exempt, so `mfa` is route middleware only.
- A forgotten `auth` leaves a route closed: a guest is refused. This also means a route machines use does not carry
  `mfa`.
- `maxAge()` and `acrValues()` are lossy projections of a requirement whose parts are bounded independently, and neither
  can express multifactor authentication or phishing resistance. `$requirement` stays authoritative.
- `$offered` is `FactorOffers::offered()`: it answers whether a factor can follow the first factor, not whether it would
  meet this requirement, so an AAL2 refusal can offer only an email code. Empty also means an unknown first factor or
  every factor disabled, so `hasConfirmedFactor` is no authority to bootstrap.
- `last_verification_age_seconds` is not operation freshness, and a multi-factor first factor can read `accepted` with
  the age `null`.
- Whatever `ActiveTenantResolver` or the application selection reads must be set before the gate, under the default
  priority too. A tenant of `null` adds no tenant part, so a tenant not yet selected means its requirement is not asked
  for and the request can pass. An `mfa` from an outer group runs before a tenant middleware on the route, and the
  priority places `mfa` before `SubstituteBindings` even when a route lists the bindings first, so a resolver must not
  rely on bound route models.
- An application replacing the priority list can fail open: if the default guard already holds a strongly
  authenticated identity, `mfa` passes for it and `auth:api` then selects another.
- The guarantee is the outermost commit's. An application that wraps `Mfa::verify()` in its own transaction on the
  storage connection makes the package's commit a savepoint, so the result reaches its closure first. Nested
  transactions stay supported. Returning a response from such a closure is safe, as `transaction()` must finish before
  it escapes; emitting it or publishing the completion inside the closure is not.
- A failed commit of the package's own takes the work waiting for it along (`Database\StorageTransaction`), on every
  supported Laravel version. The commit of an application's own outer transaction is Laravel's: Laravel 12 keeps the
  work waiting for it and runs it on the connection's next commit. An application that catches that failure and carries
  on in the same process must discard it with `app('db.transactions')->rollback($connection, 0)`.
- A listener throwing after a real commit is a separate case: the session did activate and the result is lost. That is
  an honest server error, not a commit failure.

## Implementation Anchors

- `src/Http/Middleware/EnsureMfaRequirementIsMet.php`: `handle()`, `gate()`, `isMet()`, `isExempt()`, `parse()`.
- `src/Http/Middleware/ExemptFromMfa.php`; `src/Http/HttpBindings.php`: `boot()`;
  `src/Http/MiddlewareSessionTransition.php`.
- `src/Exceptions/InsufficientAuthenticationException.php`; `src/Requirements/StepUpRefusal.php`: `of()`;
  `src/MfaManager.php`: `stepUpRefusal()`.
- `src/Context/AuthenticationContextContributor.php`; `src/MfaManager.php`: `authenticationContext()`.
- `src/Requirements/ConfiguredFreshnessGate.php`: `evaluation()`, which answers not fresh for anyone the package does
  not serve; `src/Requirements/RequirementService.php`: `requirementFor()`, `isFresh()`, `freshnessRequirement()`.
- `src/Verification/VerificationService.php`: `settled()`, `accept()`; `src/Enrollment/EnrollmentConfirmer.php`:
  `attempt()`; `src/Database/AfterStorageCommit.php`; `src/Database/StorageTransaction.php`.

## Authoritative Tests

- `tests/Feature/Http/EnsureMfaRequirementIsMetTest.php`: the matrix through the kernel: modes, evidence, operations,
  refusals, parsing, exemption in both orders, two populated guards, read-only and stateless.
- `tests/Feature/Http/RemovedFactorGateTest.php`: a recent weaker proof does not pass once the stronger factor is
  removed.
- `tests/Feature/Http/EnrolledFactorGateTest.php`: on an `enrolled` application, a first factor confirmed through a real
  enrolment gates the next request under the default transition, until the person verifies with it.
- `tests/Unit/Exceptions/InsufficientAuthenticationExceptionTest.php`: status, no header, exact header strings,
  `toArray()`.
- `tests/Feature/Requirements/StepUpRefusalTest.php`: the refusal built without a request, for a person, a pending
  caller and a caller not served, with the requirement taken as given.
- `tests/Feature/Context/AuthenticationContextContributorTest.php`: each kind of session pinned exactly.
- `tests/Feature/Verification/CommitFailureTest.php`: a failed commit on a pending verification, a step-up and a pending
  enrolment confirmation reaches the caller with neither token nor cookie, and leaves nothing to run alongside a retry,
  with a control that shows both, an outer rollback and an outer commit.
- `tests/Unit/Database/StorageTransactionTest.php`: the work of a failed commit never runs later, under a manager that
  behaves as Laravel 12's on every version; an open outer transaction keeps its own.
- `tests/Unit/Http/HttpBindingsTest.php`: the aliases and the priority, a kernel resolved before and after booting.
- `tests/Unit/Http/Middleware/ExemptFromMfaTest.php`, `tests/Unit/Requirements/ConfiguredFreshnessGateTest.php`.

## Change Triggers

Revisit this note when the gate judges anything but the composed requirement, when it starts writing or calling a
transition, when the marker takes parameters, when a key joins or leaves the context, when the result of a verification
is built outside its transaction's return, or when the transaction moves off the storage connection.
