# Recovery Codes

## Purpose

This note records how an identity's recovery codes are generated, stored, redeemed, counted and removed: why a code is a
salted hash, why a redemption checks the whole unused set as one attempt, how a new set replaces the old one with no
moment when both work or neither exists, and what a redemption leaves behind.

## Invariants

- Recovery codes are a fallback for lost factors, never a factor. They have their own table and model
  (`mfa.recovery_codes.model`, `Contracts\RecoveryCode`), no factor driver is registered for them, and they never count
  towards `isMfaEnabled()`, and a set makes no factor confirmed. An identity has one set, shared by every application;
  an application takes them only where `applications.{name}.recovery_codes.enabled` is true.
- A set is `count` codes, each `length` characters drawn with `random_int()` from `alphabet`, which samples uniformly
  without modulo bias, upper-cased as drawn and distinct within the set (a repeated code is drawn again). The settings
  give every code at least 40 bits measured after normalisation (see
  [Application configuration](application-configuration.md)); the defaults, 12 characters from a 32-character
  alphabet, give 60.
- A code is stored only as a hash made with the application's Laravel hasher (`Illuminate\Contracts\Hashing\Hasher`,
  bcrypt by default), salted, as NIST SP 800-63B-4 requires of a look-up secret below 112 bits. The hasher is the one
  the application checks passwords with, so its driver and cost apply; there is no package-specific hash.
- The plaintext codes are returned once, from `generate()`, as `Secrets\RevealedSecret` values, unformatted and in the
  order drawn. Nothing keeps them afterwards.
- A submitted code is normalised before it is checked: ASCII whitespace and hyphens removed, ASCII letters upper-cased,
  nothing else mapped. It is not checked against the configured length or alphabet, so a set issued before either
  changed still redeems. Input over 256 bytes, or over 64 characters once normalised (the longest a code can be), is
  malformed.
- A redemption is one attempt against the identity's whole unused set: every code of the current generation that is
  neither used nor replaced is checked with the hasher, a match never ends the loop, and a malformed code is checked as
  a placeholder no stored code can be and matches nothing. The work is the same whichever code matches and whether one
  does; it grows with the unused count. One attempt is one verification event.
- The identity's state row (see [Schema and models](schema-and-models.md)) holds the set's generation, which only rises,
  and the time it was generated, `null` while there is no set. Each code row holds the generation of its set, when it
  was used and when a newer set replaced it.
- Generating, redeeming and removing run in the identity's factor state transaction (see
  [Storage and transactions](storage-and-transactions.md)), so they are serialised per identity and each commits or
  rolls back as a whole.
- Every event is dispatched through `Events\EventDispatcher`, once the change it reports commits, and never carries a
  code or a hash.

## Success Path

- Generation (`RecoveryCodeService::generate()`): the identity is checked (a person, active), the application must
  accept recovery codes and the identity must have a confirmed factor. The codes are drawn and hashed before the lock is
  taken. Under the lock the checks are made again, the confirmed factor among the factors as stored; every code of the
  identity not yet replaced, used ones included, is marked replaced; the new codes are stored under the next generation;
  the generation and its time are recorded on the state row, every save required to be made; and
  `RecoveryCodesGenerated` (size, generation, actor) is queued for the commit. The codes are returned once the
  transaction has committed.
- The public path, `Mfa::generateRecoveryCodes()` (`RecoveryCodes\RecoveryCodeIssuance`), serves the signed-in person
  only, never a pending session, and answers with a `RecoveryCodes\RecoveryCodeGeneration`: the codes, or a reason.
  Nobody served is `not_found`. It captures the binding, and refuses as `not_fresh`, before the draw and again first
  under the lock, a sign-in that changed, a session not fresh for `mfa.generate_recovery_codes` and one below
  `ApplicationSettings::recoveryCodeLevel()`, since the remedy is the same stronger step-up; a refusal leaves the old
  set intact.
- Only the package's own refusals become a reason. `RecoveryCodeService::generate()` keeps its throwing contract for
  its internal callers, and is `replaceSet()`, everything up to the commit, then `reportGenerated()`. The issuance wraps
  only `replaceSet()`, where a refusal `OperationRefusedException::byPackage()` marked becomes the answer and any other
  is thrown on, rolling back, and reports outside the wrapping: a listener's exception, marked or not, is never read as
  a refusal of a set that committed, and an application's outer transaction still defers the event to its own commit.
- Redemption (`Mfa::verify(Submission::recoveryCode(...))`, then `RecoveryCodeService::admission()` and `redeem()`,
  under the identity's lock the verification holds): an inactive identity, an application that does not accept recovery
  codes, no confirmed factor as stored and an unknown first factor are refused before any hash is checked. The attempt
  then goes through `Attempts\AttemptService`, charged to the identity: the usable codes of the current generation are
  read with a locking read and all checked, and a match is marked used by `UPDATE ... SET used_at WHERE id AND used_at
  IS NULL AND replaced_at IS NULL`, which must change one row. `redeem()` records no proof and reports nothing, so the
  verification can roll the code's use back. It makes the `recovery_code` proof (method `recovery_code`, no channel, no
  reference, the purpose given, the verification generation read under the lock) and hands it to the completion seam,
  then queues `VerificationPassed`, and `RecoveryCodeService::reportRedeemed()` queues `RecoveryCodeUsed` with the
  remaining count and, when `low_count` is above 0 and the remaining count is at or below it, `RecoveryCodesLow`, in
  that order.
- Status (`RecoveryCodeService::status()`, `Mfa::recoveryCodeStatus()`, which reads the caller through
  `statusOfCaller()`): one statement on the write connection, the state row left-joined to the usable codes of its
  current generation, gives the remaining count, the generation and the time, so the count and the generation are always
  of the same set. No lock is taken.
- Removal (`RecoveryCodeService::removeSet()`, or `deleteSet()` and `reportSetRemoved()` for a removal with more to do
  before it reports): inside the transaction that removes the identity's last confirmed
  factor, every code row is deleted and the set's time cleared; the generation is kept. `RecoveryCodesRemoved` is
  queued when there was a set, used up or not, or any code row. `Lifecycle\FactorRemoval::remove()` deletes the
  factor as stored under the lock and calls it when none of the factors left there is confirmed: a pending factor does
  not keep the set, a confirmed one the failure ceiling disabled does. `Lifecycle\IdentityReset` calls it as well.
- Pruning (`RecoveryCodeService::prune($before)`): deletes the codes used, or replaced, before the time given, never a
  usable code, and leaves the state row as it is.

## Failure / Edge Cases

- Generation is refused with `OperationRefusedException`: `machine_identity`, `identity_inactive`, `type_not_enabled`
  when the application does not accept recovery codes, and `no_factor` without a confirmed factor, before the lock or
  under it. A failure partway through the replacement, a save a model event cancels included (it throws
  `WriteCanceledException`), rolls all of it back: the previous set is untouched and still
  redeems, the generation is unchanged and nothing is reported.
- With an identity's first additional factor, `RecoveryCodeIssuance::withFirstFactor()` generates a set in the change
  that confirms it, when the application accepts them and the session's known first factor followed by the
  confirmation's own proof reaches the level, without the freshness gate. `RecoveryCodesGenerated` is dispatched from
  outside the set's nested transaction, so it keeps its place among that change's events (see
  [Enrolment](enrollment.md)).
- A redemption is refused before any attempt, counted nowhere, with one `VerificationFailed` and nothing checked or
  spent: `machine_identity` or `identity_inactive`; `not_accepted` for an enrolment, which a recovery code cannot
  confirm; `type_not_enabled` when the application does not accept recovery codes; `no_factor` without a confirmed
  factor; and `not_accepted` when the identity has no sign-in the proof store knows of, so a single-use code is never
  spent for no proof (stricter than a factor's verification, which proves nothing then but still passes).
- A lockout of the identity or the IP address refuses the attempt before anything is checked: `locked`, with the time
  it lifts, or none when the identity's run of failures has reached the failure ceiling, which only a success or a
  reset clears.
- A sign-in that ended, or a last confirmed factor that went, while the redemption waited for the lock: one counted
  failure (`not_accepted` or `no_factor`), nothing checked.
- A sign-in that ended while the code was being checked leaves no sign-in to record the proof on: the redemption throws
  `ProofRefusedException`, so the code's use rolls back, nothing is counted and nothing is reported. A redemption never
  passes without its proof.
- A factor deletion a model event cancels throws `WriteCanceledException` and keeps the set.
- No set, or every code used: one counted attempt, `invalid_code`, no hash checked.
- Two redemptions of one code: the lock serialises them, and the second finds the code used; a redemption that read the
  set before another used or replaced its code finds, when it marks it, that no row changed, and fails `invalid_code`.
- A redemption racing a replacement waits for the identity's lock: it sees the old set intact or the new one, never
  both and never neither, and a code of an earlier generation never redeems.
- An application that switches its hashing driver with `hashing.*.verify` on (Laravel's default) makes every existing
  set fail with the hasher's `RuntimeException` until a new set is generated, as it does for passwords.
- The default seams hand the proof to the store once the code's use commits: the two are not one atomic step, and a
  store that refuses the proof throws `ProofRefusedException` with the code already used. A seam's refusal, and a
  surrounding transaction on the storage connection that rolls back, leave the code unused with nothing recorded or
  reported.

## Implementation Anchors

- `src/RecoveryCodes/RecoveryCodeService.php`: `generate()`, `admission()`, `redeem()`, `reportRedeemed()`, `status()`,
  `removeSet()`, `prune()`. `src/RecoveryCodes/RecoveryCodeIssuance.php`: the public path's gate.
- `src/RecoveryCodes/RecoveryCodeGenerator.php`, `src/RecoveryCodes/RecoveryCodeNormalizer.php`,
  `src/RecoveryCodes/RecoveryCodeMatcher.php`, `src/RecoveryCodes/RecoveryCodeSettings.php`.
- `src/RecoveryCodes/Redemption.php`, `src/RecoveryCodes/RecoveryCodeStatus.php`.
- `src/Lifecycle/FactorRemoval.php`: `remove()`; `src/Lifecycle/IdentityReset.php`.
- `src/Attempts/AttemptService.php`: `attempt()`; `src/Attempts/RequestIp.php`.
- `src/Models/RecoveryCode.php`, `src/Concerns/ActsAsRecoveryCode.php`, `src/Contracts/RecoveryCode.php`.

## Authoritative Tests

- `tests/Unit/RecoveryCodes/RecoveryCodeGenerationTest.php`
- `tests/Unit/RecoveryCodes/RecoveryCodeRedemptionTest.php`
- `tests/Unit/RecoveryCodes/RecoveryCodeServiceTest.php`
- `tests/Unit/RecoveryCodes/RecoveryCodeMatcherTest.php`
- `tests/Unit/RecoveryCodes/RecoveryCodeNormalizerTest.php`
- `tests/Unit/RecoveryCodes/RecoveryCodeGeneratorTest.php`
- `tests/Feature/Lifecycle/RemovingFactorTest.php`
- `tests/Integration/Database/RecoveryCodeRaceTest.php`
- `tests/Integration/Database/StorageConnectionRecoveryCodesTest.php`

## Change Triggers

- A change to how codes are drawn, normalised or hashed, or to the bounds of a malformed code.
- A redemption that could stop before checking every unused code, or check anything outside the identity's lock.
- A replacement that could leave a moment with both sets or neither, or a set removed outside the factor's removal.
- The freshness and level gates being applied to generation, or redemption moving into the unified verification.
