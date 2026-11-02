# Attempts and Lockout

## Purpose

This note records how the package counts failed attempts and refuses further ones: the durable counts on the factor and
identity state rows, the temporary throttles in `mfa_attempts`, when each locks what and for how long, what resets each
counter, the failure ceiling that disables a factor or bounds the identity, and why parallel guesses cannot overrun a
cap. Lifting a lockout, enabling a disabled factor and resetting the identity's run are separate operations, and all
are described here.

## Invariants

- Every attempt goes through `Attempts\AttemptService::attempt()`, with an `Attempts\Attempt` naming the identity whose
  own pending or active session made it, the identity's factor (or none, for a recovery code), the purpose, the
  request's address as resolved through the trusted proxies (`$request->ip()`) and the application. The caller checks
  the session and the factor's owner first: `VerificationService::verify()` verifies only the current identity's own
  factor and refuses another's with `FactorOwnershipMismatchException` before anything is counted, so nobody is charged
  for an attempt someone else made.
- An attempt is counted against three scopes (`Enums\AttemptScope`):
  - the factor: `consecutive_failures` on its row, its failures in a row. From `mfa.attempts.factor_limit` on, each
    failure locks it for `lockout_seconds`, recorded as a row of `mfa_attempts` (scope `factor`) whose window ends when
    the lockout does. At `failure_ceiling` (at most 100) the factor is disabled instead: `disabled_at` is stamped and
    `FactorDisabled` dispatched, and no lockout is applied;
  - the identity: `consecutive_failures` on its state row, its run of failures across every factor and recovery code;
    and its failures within `window_seconds`, a row of `mfa_attempts` (scope `identity`). When that count reaches
    `identity_limit`, `locked_until` on its state row is set `lockout_seconds` ahead and `LockoutApplied` dispatched
    with no factor. When the run reaches `failure_ceiling`, the failure disables the factor it was made against
    (`FactorDisabled`), and from then on every failure does, while an attempt that names no stateful factor (a recovery
    code, a factor that keeps no state) is refused with an identity-scoped `Lockout` that has no end, until a success
    or `resetIdentityFailures()` clears the run. Guesses spread across factors and recovery codes are bounded as guesses
    at one factor are;
  - the address: its failures within `window_seconds`, a row of `mfa_attempts` (scope `ip`). At `ip_limit` it is refused
    until its window ends. The address is counted by the client it stands for (an IPv4 address, the IPv4 address an IPv6
    address carries, or an IPv6 /64).
- An attempt naming a stateful factor that is not among the identity's factors as locked (removed by a concurrent
  change, or another identity's) is answered `AttemptOutcome::notFound()` before anything else: the verification does
  not run and nothing is counted, so a stale instance is never verified.
- A refused attempt is refused before the verification runs, in the order a factor or identity at the ceiling, then the
  lockout that ends last (`Lockout::strictest()`), and counted nowhere: it never extends a lockout or a throttle. The
  outcome carries the `Attempts\Lockout`: its scope and when it ends, or no time at the ceiling.
- The verification is handed the factor as stored under the lock (`Attempts\LockedFactors::find()`), not the instance
  the caller read, so a replaced secret is the one checked, and what it writes to that factor commits with the count.
  A delivered code is checked by the code service inside the same transaction, against the code the request's session
  was sent, so the code it uses up commits with the count too.
- A delivered code's challenge keeps its own attempt budget (see [Delivered Codes](delivered-codes.md)); a guess at it
  is also an attempt here, counted against the factor, the identity and the address like any other.
- Only a success resets a durable count: the factor's failures in a row are reset only by a success of that factor, and
  the identity's run only by a success of any. A success resets no other factor's count, lifts no lockout or throttle,
  and takes no slot of the address's window. It enables the identity's other factors the failure ceiling disabled, since
  the person has proved another factor, but keeps their failures in a row, so the next failure of one disables it
  again.
- A lockout ending forgives nothing: the factor's failures in a row stay at or past the limit, so its next failure locks
  it again, one guess per lockout period, until a success or the failure ceiling.
- Sending or resending a code resets no count and lifts no lockout: the code service writes only the code's challenge,
  and the verification service's challenge writes nothing else.
- `mfa_attempts` rows are keyed by `Attempts\AttemptKeys`: an HMAC-SHA256 digest of the scope and subject, keyed with a
  key derived from `app.key`, so the table names no factor, identity or address. Rotating the application key starts
  every throttle afresh and keeps the durable counts.
- Nothing depends on a cache: every count, lockout and throttle is in the database on the storage connection, read from
  the write connection.
- `liftLockout($identity, $factor, $actor)` deletes the factor's lockout row, or clears the identity's `locked_until`
  and its window row, under the identity's factor state lock, and dispatches `LockoutLifted` with the actor when a live
  lockout was lifted. The factor must be among the identity's locked factors, or nothing is lifted. It keeps the
  durable counts and leaves a disabled factor disabled.
- `enableFactor($factor)` clears `disabled_at` and the factor's failures in a row under the lock, and leaves any lockout
  to end on its own. It reports nothing: rebinding and resetting, which call it, report themselves.
- `resetIdentityFailures($identity)` clears the identity's run under the lock, and nothing else.
- `lockout()`, `liftLockout()`, `enableFactor()` and `resetIdentityFailures()` are the public operations; `attempt()` is
  internal to the verification paths.
- A challenge another owner sends and consumes (an authentication layer's `mfa` challenge, or the package's own
  `Codes\PackageChallengeGateway`) is counted through `Attempts\ChallengeCounters`, inside the owner's transaction on
  the storage connection: `isUsable()` reads the lockouts under the identity's lock (`lockedOut()`, without an address)
  and checks the factor is the identity's, confirmed, of an enabled type and accepted after the session's first factor;
  `report()` counts the outcome as `attempt()` does, without an address. Both refuse outside a transaction, so the lock
  is held until the owner commits and parallel guesses cannot overrun the identity's cap (see
  [Seam Contracts](seam-contracts.md)).
- A factor that is not an Eloquent model implementing `EloquentFactor` keeps no state: it has no failures in a row,
  lockout or ceiling of its own, and its attempts are counted against the identity and the address, so the identity's
  ceiling refuses it as it does a recovery code.

## Success Path

- The address's slot is taken first, by `Attempts\IpThrottle::take()`, in single statements of
  `Attempts\AttemptStore::take()`: one `UPDATE` adds the attempt to a live window with room or restarts an ended one, an
  `insertOrIgnore` creates a missing row, and a live window ending elsewhere (after a change of `window_seconds`) is
  counted in as stored. A full window answers its end, and the attempt is refused without opening a transaction.
- `FactorStateTransaction::forIdentity()` then opens the transaction on the storage connection, locks the identity's
  state row and its factors in that order (see [Storage and Transactions](storage-and-transactions.md)), and hands over
  the factors as stored under the lock. The service reads the identity's state, finds the attempted factor among the
  locked ones, reads the factor's lockout row, and refuses the attempt while a lockout applies.
- Otherwise it runs the verification inside the transaction, so a driver's own change (a TOTP step) and the verification
  service's record of a success (the delivered code used up, `last_used_at`) commit with the count, and counts the
  outcome on the locked rows: a success resets as above; a failure records the identity's window, in one
  upsert, and its run, then the factor's failures in a row, its lockout or its disablement.
- The identity's state row is read `FOR UPDATE`, a lock the transaction already holds, so a lockout committed while the
  attempt waited is never answered from an older snapshot. The throttle rows are read with plain reads: a locking read
  of a missing key would take a gap lock on MySQL and let two identities' first failures deadlock.
- After the commit, the address's slot is given back unless the attempt failed: a success or a refusal is not a failure
  of the address. The events the attempt raised are then dispatched (see [Event Catalogue](event-catalogue.md)); a
  listener that throws leaves the count, and the address's charge, standing.

## Failure / Edge Cases

- Parallel guesses for one identity wait on its state lock, so the second reads the counts and lockouts the first
  committed: with a limit of one, one guess reaches a driver and the next is refused. Parallel guesses from one address
  for several identities each take a slot in one statement, so the slots taken never pass `ip_limit`.
- A verification that throws rolls the transaction back, counting nothing, and the address's slot is given back before
  the exception propagates; the same holds when recording a success fails, so a code is never used up without its
  count. A database error is never read as a refusal or a pass.
- The identity's window is counted with one upsert, never an `UPDATE` that may find no row: inside the transaction,
  such an update holds a gap lock on MySQL until the commit, and two identities recording their first failure in the
  same gap would deadlock on each other's insert.
- An attempt made inside a transaction the application opened on the storage connection, after it has read, may read
  the throttle rows from that transaction's snapshot on MySQL (`REPEATABLE READ`), and so miss a temporary lockout
  committed in the meantime. The identity's state and its factors are read with locking reads and are not affected; the
  guide asks applications not to verify inside a transaction of their own.
- The identity's window starts with its first failure and ends `window_seconds` later; failures spread wider than it
  never lock the identity, whatever its run.
- The failure ceiling takes precedence over the factor limit: a failure that reaches both disables the factor and
  applies no lockout. A disabled factor is refused as disabled whatever its lockout.
- Lifting a lockout that already ended, or was never applied, lifts nothing, reports nothing and answers `false`.
- `Mfa::verify()` reports a refused attempt as `MfaVerificationFailed` with the `locked` reason and the lockout's detail
  (the factor, the identity, the address, a factor disabled at the ceiling or an identity at it), a factor not found as
  `not_found`, and `false`.
- A setting out of its bounds fails closed with an `InvalidArgumentException` naming the key when it is read, inside the
  transaction, which rolls back; the package checks every setting at boot, so this is a misconfiguration that never
  reaches a person's verification.
- Each counter and how it ends is listed in the [attempts guide](../guides/attempts.md#the-counters).

## Implementation Anchors

- `src/Attempts/AttemptService.php`: `attempt()`, `lockout()`, `liftLockout()`, `enableFactor()`,
  `resetIdentityFailures()`.
- `src/Attempts/LockedFactors.php`: the attempted factor found among the locked ones.
- `src/Attempts/AttemptStore.php`: the single-statement window counts (`take()`, `record()` as an upsert, `giveBack()`)
  and the lockout rows (`hold()`, `forget()`, `read()`).
- `src/Attempts/AttemptKeys.php`: the keyed digests and the canonical address.
- `src/Attempts/IpThrottle.php`: the address's slot taken and given back (`take()`, `giveBack()`) and its throttle
  (`lockout()`).
- `src/Attempts/Attempt.php`, `src/Attempts/AttemptOutcome.php`, `src/Attempts/Lockout.php`,
  `src/Enums/AttemptScope.php`.
- `src/Attempts/AttemptSettings.php`: `mfa.attempts.*` and their bounds.
- `src/Verification/VerificationService.php`: `verify()` making the attempt and reporting a refusal as `locked`.
- `src/Support/FactorStateTransaction.php`: the lock the count and lockout are read under.

## Authoritative Tests

- `tests/Unit/Attempts/AttemptServiceTest.php`
- `tests/Unit/Attempts/AttemptStoreTest.php`
- `tests/Unit/Attempts/AttemptKeysTest.php`
- `tests/Unit/Attempts/IpThrottleTest.php`
- `tests/Unit/Attempts/LockoutTest.php`
- `tests/Unit/Attempts/LockedFactorsTest.php`
- `tests/Unit/Attempts/AttemptSettingsTest.php`
- `tests/Integration/Database/ParallelAttemptsTest.php` (MySQL and PostgreSQL)
- `tests/Unit/Verification/VerificationServiceTest.php` `testAnAttemptOnAnotherIdentitysFactorChargesNobody`,
  `testAFailureIsCountedAgainstTheRequestsAddress`, `testTheAttemptReachingTheLimitLocksTheFactor`,
  `testARemovedFactorIsNotFoundWithoutReachingTheDriver`, `testTheDriverVerifiesTheFactorAsStored`,
  `testASuccessIsRecordedWithItsCount`, `testSendingACodeResetsNothing`
- `tests/Feature/OtpLifecycleTest.php` `testEmailChallengeResetsNothing`
- `tests/Feature/TotpLifecycleTest.php` `testChallengePreservesTheLockoutEndAfterLockout`

## Change Triggers

Update this note when any of the following change:

- the scopes an attempt is counted against, or what a success or a send resets
- the rule that a refused attempt reaches no driver and counts nowhere
- the failure ceiling, its precedence over the factor limit, how a disabled factor is enabled again, or what the
  identity's run at the ceiling refuses
- the lock the count and lockout are read under, or the single-statement counting of the address
- the `mfa.attempts.*` keys or their bounds
- how `mfa_attempts` rows are keyed, or what a factor's row records
