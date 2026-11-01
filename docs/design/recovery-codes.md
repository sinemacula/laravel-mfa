# Recovery Codes

## Purpose

This note records how an identity's recovery codes are generated, stored, redeemed, counted and removed: why a code is a
salted hash, why a redemption checks the whole unused set as one attempt, how a new set replaces the old one with no
moment when both work or neither exists, and what a redemption leaves behind.

## Invariants

- Recovery codes are a fallback for lost factors, never a factor. They have their own table and model
  (`mfa.recovery_codes.model`, `Contracts\RecoveryCode`), no factor driver is registered for them, and they never count
  towards `isMfaEnabled()` or `Mfa::isSetup()`. An identity has one set, shared by every application; an application
  takes them only where `applications.{name}.recovery_codes.enabled` is true.
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

- Generation (`RecoveryCodeService::generate()`, `Mfa::generateRecoveryCodes()`): the identity is checked (a person,
  active), the application must accept recovery codes and the identity must have a confirmed factor. The codes are
  drawn and hashed before the lock is taken. Under the lock the checks are made again, the confirmed factor among the
  factors as stored; every code of the identity not yet replaced, used ones included, is marked replaced; the new codes
  are stored under the next generation; the generation and its time are recorded on the state row; and
  `RecoveryCodesGenerated` (size, generation, actor) is queued for the commit. The codes are returned once the
  transaction has committed.
- Redemption (`RecoveryCodeService::redeem()`, `Mfa::redeemRecoveryCode()`): refusals first (below), then the attempt
  through `Attempts\AttemptService`, charged to the identity and to the request's IP address as resolved through the
  trusted proxies. Under the lock: the sign-in and a confirmed factor are checked again; the verification generation
  is read; the usable codes of the current generation are read with a locking read and all checked; a match is marked
  used by `UPDATE ... SET used_at WHERE id AND used_at IS NULL AND replaced_at IS NULL`, which must change one row. The
  attempt service counts the outcome in the same transaction. Once it has committed, a success records a
  `recovery_code` proof (method `recovery_code`, no channel, no reference, the purpose given, the verification
  generation read under the lock) and dispatches `VerificationPassed`, `RecoveryCodeUsed` with the remaining count and,
  when `low_count` is above 0 and the remaining count is at or below it, `RecoveryCodesLow`, in that order.
- Status (`RecoveryCodeService::status()`, `Mfa::recoveryCodes()`): one statement on the write connection, the state
  row left-joined to the usable codes of its current generation, gives the remaining count, the generation and the
  time, so the count and the generation are always of the same set. No lock is taken.
- Removal (`RecoveryCodeService::removeSet()`): inside the transaction that removes the identity's last confirmed
  factor, every code row is deleted and the set's time cleared; the generation is kept. `RecoveryCodesRemoved` is
  queued when there was a set, used up or not, or any code row. `Lifecycle\LifecycleService::disable()` calls it when
  none of the factors left under the lock is confirmed: a pending factor does not keep the set, a confirmed one the
  failure ceiling disabled does.
- Pruning (`RecoveryCodeService::prune($before)`): deletes the codes used, or replaced, before the time given, never a
  usable code, and leaves the state row as it is.

## Failure / Edge Cases

- Generation is refused with `OperationRefusedException`: `machine_identity`, `identity_inactive`, `type_not_enabled`
  when the application does not accept recovery codes, and `no_factor` without a confirmed factor, before the lock or
  under it. A failure partway through the replacement rolls all of it back: the previous set is untouched and still
  redeems, the generation is unchanged and nothing is reported.
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
- No set, or every code used: one counted attempt, `invalid_code`, no hash checked.
- Two redemptions of one code: the lock serialises them, and the second finds the code used; a redemption that read the
  set before another used or replaced its code finds, when it marks it, that no row changed, and fails `invalid_code`.
- A redemption racing a replacement waits for the identity's lock: it sees the old set intact or the new one, never
  both and never neither, and a code of an earlier generation never redeems.
- An application that switches its hashing driver with `hashing.*.verify` on (Laravel's default) makes every existing
  set fail with the hasher's `RuntimeException` until a new set is generated, as it does for passwords.
- The proof is handed to the store once the code's use commits: the two are not one atomic step, and a store that
  refuses the proof throws `ProofRefusedException` with the code already used. Inside a surrounding transaction on the
  storage connection that rolls back, the code stays unused and nothing is recorded or reported.
- The freshness and assurance-level gates on generation, and the unified verification result, are not applied yet.

## Implementation Anchors

- `src/RecoveryCodes/RecoveryCodeService.php`: `generate()`, `redeem()`, `status()`, `removeSet()`, `prune()`.
- `src/RecoveryCodes/RecoveryCodeGenerator.php`, `src/RecoveryCodes/RecoveryCodeNormalizer.php`,
  `src/RecoveryCodes/RecoveryCodeMatcher.php`, `src/RecoveryCodes/RecoveryCodeSettings.php`.
- `src/RecoveryCodes/Redemption.php`, `src/RecoveryCodes/RecoveryCodeStatus.php`.
- `src/Lifecycle/LifecycleService.php`: `disable()`.
- `src/Attempts/AttemptService.php`: `attempt()`; `src/Attempts/RequestIp.php`.
- `src/Models/RecoveryCode.php`, `src/Concerns/ActsAsRecoveryCode.php`, `src/Contracts/RecoveryCode.php`.

## Authoritative Tests

- `tests/Unit/RecoveryCodes/RecoveryCodeGenerationTest.php`
- `tests/Unit/RecoveryCodes/RecoveryCodeRedemptionTest.php`
- `tests/Unit/RecoveryCodes/RecoveryCodeServiceTest.php`
- `tests/Unit/RecoveryCodes/RecoveryCodeMatcherTest.php`
- `tests/Unit/RecoveryCodes/RecoveryCodeNormalizerTest.php`
- `tests/Unit/RecoveryCodes/RecoveryCodeGeneratorTest.php`
- `tests/Unit/Lifecycle/LifecycleServiceTest.php`
- `tests/Integration/Database/RecoveryCodeRaceTest.php`
- `tests/Integration/Database/StorageConnectionRecoveryCodesTest.php`

## Change Triggers

- A change to how codes are drawn, normalised or hashed, or to the bounds of a malformed code.
- A redemption that could stop before checking every unused code, or check anything outside the identity's lock.
- A replacement that could leave a moment with both sets or neither, or a set removed outside the factor's removal.
- The freshness and level gates being applied to generation, or redemption moving into the unified verification.
