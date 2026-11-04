# Factor lifecycle

## Purpose

This note documents what happens to a factor after it is enrolled: how it is listed, what a removal checks and when,
what a reset does and in which order, what unlocking leaves alone, and what pruning may and may not delete. The API is
in [Factor lifecycle](../guides/lifecycle.md).

## Invariants

- Listing serves `mfa.list_factors`, on an active or an allowed pending session, and never hides a factor: pending ones
  and another application's are listed. Ownership and ids are compared exactly in PHP, through
  `FactorStateTransaction::snapshot()` and `LockedFactors::withId()`, since a database's collation may not be exact and
  a custom model's key may be an integer. Set-up is a confirmed summary, derived from the list.
- A removal is decided twice by one set of checks, `Lifecycle\RemovalGuard`: on a snapshot taking no lock, then in the
  identity's factor state transaction on the factors as stored under the lock, with the caller resolved again and
  compared through `CallerContextResolver::still()`. The first exists so what is refused anyway waits for nothing and
  takes no lock; the second is the one that counts, and the only one that asks the bound `FactorChangeGate`.
  `Passkeys\PasskeyChangeGate::removing()` runs only the second, as it is already inside its caller's transaction; it
  captures the sign-in before the lock and compares it under the lock in the same way, so its refusals match: no
  sign-in is `not_fresh`, and one that changed is `not_found`.
- The check order is fixed: identity inactive, not found (unknown, someone else's, or another application's), not
  confirmed, not fresh, last factor. An application never deletes a factor enrolled through another, a passkey's
  included: the credential being identity-level makes no exception, and the refusal rolls authentication's own
  credential removal back.
- `LastFactorPolicy` receives the factors. It may be asked before the identity's lock inside a caller's transaction,
  where taking a factor's lock would break the lock order. `RequiredFactorPolicy` therefore takes no lock, and reads a
  passkey's association without one: an association changes only with its factor under that lock, so a read older than
  the lock can only miss one, which counts as no association and fails closed.
- "Another factor" for the step-up is any other confirmed factor, including one disabled at the ceiling or of a type
  this application does not enable. Relaxing that to factors provable here would let making another factor unavailable
  stand in for proving it. A person stuck without a provable factor is an actor's reset.
- The freshness of a removal is the bound `FactorChangeGate`'s, asked under the lock only, with the factor's id and
  the requirement the application configures for `mfa.remove_factor`. The check before the lock asks it nothing, since
  a gate over an authentication layer locks that layer's session row. The default holds the session to the freshness
  gate's own requirement on the proofs made without the factor, so a stricter requirement of an adapter's cannot be
  satisfied by the removed factor alone. A freshness gate with no requirement to judge by refuses while another factor
  remains. A recovery code's proof has no reference, so it counts as made without the factor.
- `OperationRefusedException` becomes a refusal only from the checks, wrapped in
  `RefusedUnderLockException::carrying()`. The mutation is outside that wrapper, so a revoker or a transition throwing
  one propagates and rolls back: it failed, it was not refused. An exception a listener throws after the commit is not
  one of these either, so what committed is never reported as refused.
- A removal's order is the lock order: the factor and its association, with the last confirmed factor the recovery code
  set (`deleteSet()`), then what the session keeps is read and `SessionRevoker::factorRemoved()` runs with the factor
  and the sign-in the removal is made from, the requirement is evaluated again, and a shortfall goes to the transition
  unless the revoker judged the session itself. Every package row has changed before a session seam runs, so a package
  row is never locked after a session row. `FactorRemoved` is queued after that synchronous security work, then
  `reportSetRemoved()` queues `RecoveryCodesRemoved`. Moving them ahead of `factorRemoved()` would put their listeners
  ahead of the default revoker's after-commit restoration of the proofs the current session keeps.
- A revoker that judges the current session itself, as an authentication layer's does, says so with
  `RemovalRevocation::judged()`, and what it returns reaches the caller as `FactorRemovalResult::$completion`: a layer's
  result carrying the pending session's new credential, say. The package still reports the requirement it finds
  outstanding, as its own assessment; the layer's result is the authoritative outcome, as it may end the session or
  return it to pending by rules of its own. Handing the shortfall to the transition as well would return the session to
  pending twice.
- Proofs forgotten on the session are not restored if the transaction rolls back, as a snapshot put back could undo a
  later invalidation. The failure is closed: the session verifies again.
- A reset's order is the lock order: lockouts and counts, every factor and enrolment, the recovery set, the obligation,
  the generation, then `SessionRevoker::revokeAll()`. Every lockout lifts before any factor goes, so every
  `LockoutLifted` precedes every removal event, and the factors are taken in id order so the events are deterministic.
- A reset removes every factor of the identity, whatever its stored state, as it is the remedy for one that cannot be
  read. A factor whose summary, status or deadline throws is not read for a lift, so its deadline goes with its row; it
  gets no `FactorRemoved` or `EnrollmentAbandoned`, since its summary cannot be built honestly, and
  `FactorsReset::$unreadableFactors` counts it.
  The event context is captured before the revocation, which could clear the authentication context it reads.
- A reset advances the generation itself, as a rebound revoker may not. With the default revoker it therefore moves
  twice; what is specified is that it only ever goes up, so nothing depends on the increment.
- A reset writes the obligation to the stated value, so `false` clears an earlier `true`, and it does not call
  `SessionReevaluation`: every session is revoked.
- A failure ceiling's `disabled_at` and failures in a row survive unlocking. Only temporary lockouts lift, and a
  factor's is `locked_until` on its row, so a removal takes it along.
- Saves of the identity's state that a model event cancels throw (`WriteCanceledException`), so a reset cannot commit
  with its lockout or failures intact, and an unlock cannot report a lockout lifted that stays in force.
- `ActiveTenantResolver` is authoritative: it is what requirements are composed with, read from validated session
  context, and `RequirementService::requirementFor()` is the one place that asks it, so re-evaluation after any factor
  change (removal, enrolment, a passkey's registration) and enforcement agree. `EventContextResolver` promises
  descriptive metadata only, so omitted audit data must never drop a tenant requirement. Its default names no tenant.
- Pruning deletes only what cannot matter: retention's floor is a day and the longest send window a day, so no send cap
  is shortened; a throttle row whose window has ended counts nothing, so no lockout is lifted. Expiry and window
  predicates are on the deleting statement itself, so a row a concurrent attempt has just renewed stays. It holds no
  long lock: limited statements for mass deletes, one owner's lock at a time for an enrolment.
- Context of an expiry is built from the row (`EventDispatcher::ownerContext()`), since a scheduled run's session or
  tenant has nothing to do with the owner.
- A session left short by a removal is held to the whole requirement on its next request. `mfa` judges the structured
  requirement against the proofs that remain, so a recent proof that does not meet it does not pass, and with the
  default `SessionTransition`, which changes nothing, that gate is what keeps the promise (see
  [Route Gate](route-gate.md)).

## Success Path

1. `Mfa::removeFactor()`: resolve the caller, capture its binding, run the guard on a snapshot; open the transaction;
   compare the caller; run the guard on the locked factors; `FactorRemoval::remove()`; commit; report.
2. `Mfa::resetIdentity()`: refuse a blank reason or a machine; open the transaction; do the work above; commit; report.
3. `Mfa::prune()` (`RecordPruner`): for each enrolment past the retention, lock its owner
   (`FactorStateTransaction::forOwner()`), read it again, discard or forget it; then the limited deletes.

## Failure / Edge Cases

- A sign-in that changed before the lock is `not_found`, a factor gone by then too, and a policy that refuses only the
  second time is `last_factor`.
- No sign-in the proof store knows of is `not_fresh`, whatever a bound gate answered: there is nothing to compare under
  the lock.
- A reset and a verification serialise: the reset wins and the verification fails, or the verification commits first and
  keeps its success while the reset invalidates its proof. Serialisation cannot turn an earlier committed success into a
  failure.
- An inactive identity is refused a removal, and can be reset.
- `false` from unlocking the identity means no live lockout was lifted, not that nothing changed: its window count is
  cleared.
- Mass deletes fire no model event; only the row-by-row enrolment deletion can be cancelled by one.

## Implementation Anchors

- `src/Lifecycle/LifecycleService.php`, `RemovalGuard.php`, `FactorRemoval.php`, `FactorRemovalResult.php`,
  `IdentityReset.php`, `RequiredFactorPolicy.php`, `NoSelfServiceRecovery.php`, `RecordPruner.php`, `PruneResult.php`.
- `src/Factors/FactorService.php`: `factors()`, `factor()`; `src/Attempts/LockedFactors.php`: `withId()`.
- `src/Support/FactorStateTransaction.php`: `forOwner()`, `snapshot()`; `src/Support/FactorOwnerColumns.php`: `owns()`.
- `src/Passkeys/PasskeyChangeGate.php`: `remove()`; `src/Passkeys/PasskeyAssociations.php`: `associates()`.
- `src/Http/Middleware/EnsureMfaRequirementIsMet.php`: the gate a session left short is held to.
- `src/Contracts/LastFactorPolicy.php`, `SelfServiceRecovery.php`, `ActiveTenantResolver.php`, `FreshnessGate.php`.
- `src/Requirements/RequirementService.php`: `requirementFor()`, `freshnessRequirement()`;
  `src/Requirements/SessionReevaluation.php`; `src/Requirements/ReenrollmentObligation.php`: `record()`.
- `src/Attempts/AttemptService.php`: `liftLockout()`, `resetIdentityFailures()`; `src/Attempts/AttemptStore.php`:
  `prune()`.
- `src/Database/BoundedDelete.php`; `src/Events/EventDispatcher.php`: `ownerContext()`; `src/Console/PruneCommand.php`.

## Authoritative Tests

- `tests/Feature/Lifecycle/RemovingFactorTest.php`: every refusal and its order, the step-up with another factor and a
  stricter gate, the policy asked twice, a change made before the lock, revocation, re-evaluation with a tenant,
  rollbacks, event order.
- `tests/Feature/Lifecycle/ResettingIdentityTest.php`: what goes, event order, the obligation surviving and ending, both
  orders of a verification racing a reset, recovery codes and old grants.
- `tests/Feature/Lifecycle/UnlockingTest.php`, `tests/Feature/Lifecycle/PruningTest.php`,
  `tests/Feature/Lifecycle/SelfServiceRecoveryTest.php`.
- `tests/Integration/Database/LifecycleRaceTest.php`: overlapping removals and resets on MySQL and PostgreSQL.
- `tests/Feature/Http/RemovedFactorGateTest.php`: a recent weaker proof does not pass the gate once the stronger factor
  is removed.
- `tests/Unit/Lifecycle/RequiredFactorPolicyTest.php`, `tests/Unit/Factors/FactorServiceTest.php`,
  `tests/Feature/Passkeys/PasskeyChangeGateTest.php`.

## Change Triggers

Revisit this note when the lock order changes, when a new entry point removes factors, or when a new record needs
pruning.
