# Backup Code Consumption

## Purpose

This note documents the package's backup-code single-use contract. Backup codes are cryptographic recovery credentials:
once consumed, a code must never verify a second time. The implementation has to defend that property against
concurrent requests, not just sequential ones.

## Invariants

- Each backup code is one row on the factors table, driver `'backup_code'`, with the SHA-256 digest of the plaintext
  stored on the `secret` column. Plaintext is never persisted.
- `secret` is encrypted at rest by the shipped model's `encrypted` cast, so conditional-UPDATE-in-WHERE is not a
  viable pattern; the encrypted ciphertext is non-deterministic.
- Consumption is therefore done under the owner's lock: inside `Support\FactorStateTransaction`, which locks the
  owner's identity state row and then its factors, double-check the hash against the factor as stored under the lock,
  null the secret column, commit.
- The transaction runs on the storage connection (`mfa.storage.connection`), where every package table lives; a
  factor model on another connection is refused when the package boots and before the transaction opens (see
  [Storage and transactions](storage-and-transactions.md)).
- Hashing is SHA-256 rather than a slow password hash. Backup codes are random strings drawn uniformly from
  `mfa.recovery_codes.alphabet` via `random_int`, `mfa.recovery_codes.length` long, which together carry at least 40
  bits measured after normalisation (the package checks this when it boots); a password hash would add latency
  without meaningful extra security against credential stuffing.
- Verification of the candidate code against the stored hash uses `hash_equals` — constant-time comparison, closing
  the timing-oracle primitive.
- Enrolment is an atomic replace, not an append. `issueBackupCodes()` runs in the identity's factor state transaction,
  deletes every existing `backup_code` row for the identity, inserts the freshly-minted batch, and returns the plaintext
  set exactly once. There is no window where both the old and new codes would verify, and a consumption racing the
  rotation waits for it.
- Non-Eloquent factors have no row to consume. The constant-time hash match alone is the verification result; consumers
  that ship a non-Eloquent factor implementation are responsible for their own single-use storage.

## Success Path

- The caller submits a plaintext code to `MfaManager::verify('backup_code', $factor, $code)`.
- `BackupCodeDriver::verify()` reads `$factor->getSecret()`, rejects null or empty secrets, and runs
  `hash_equals($stored, sha256($code))`.
- On a match against an Eloquent factor, the driver enters `consumeAtomic()`: runs
  `FactorStateTransaction::forFactor()` for the factor's owner, finds the factor among the owner's factors read under
  the lock, compares the candidate's hash with the stored one again, writes `null` to the secret column, commits.
- The verification service's `applyVerificationOutcome()` then runs `recordVerification()` on the factor (stamps
  `verified_at`, resets attempts, clears any pending code) and persists; `finalizeVerification()` writes the
  identity-level verification through the bound store and dispatches `MfaVerified`.
- A fresh batch via `issueBackupCodes()` deletes old rows, inserts new rows (each with the SHA-256 digest on
  `secret`), dispatches `MfaFactorEnrolled` once per new code, and returns the plaintext list to the caller.

## Failure / Edge Cases

- A wrong candidate fails the constant-time comparison before any lock is acquired. There is no row mutation and the
  verification service increments the factor's attempt counter.
- Two concurrent requests submitting the same valid code race on the owner's lock. The winner consumes the row and
  returns `true`; the loser re-reads a secret that is now `null`, fails its second hash check, and returns `false`
  without mutating anything.
- If the row is deleted by a concurrent actor between the initial hash check and the lock, it is missing from the
  factors read under the lock and consumption returns `false`. The verification service treats this as a verification failure
  with the standard classification.
- A stored `null` or empty secret short-circuits to `false` before the lock is acquired. This covers the already-
  consumed state and the stale-in-memory-but-cleared-in-DB state.
- `generateSet()` rejects a `$count` of zero or negative with `InvalidArgumentException`. Consumers cannot
  accidentally mint an empty batch that would still dispatch a rotation event with no replacement codes.
- Rotation runs inside a single transaction on the storage connection. A delete without an insert is not possible; a
  failure mid-rotation rolls back both, leaving the prior batch intact.

## Implementation Anchors

- `src/RecoveryCodes/BackupCodeDriver.php`: `verify()`, `consumeAtomic()`, `hash()`, `generateSecret()`,
  `generatePlaintextCode()`, `generateSet()`, `issueChallenge()` (no-op).
- `src/RecoveryCodes/RecoveryCodeService.php`: `issueBackupCodes()`, `rotateBackupCodeBatch()`.
- `src/RecoveryCodes/RecoveryCodeBindings.php`: `backupCodes()`, the driver's construction from config.
- `src/Models/Factor.php`: `secret` `encrypted` cast, `secret` included in `$hidden`.
- `src/Contracts/EloquentFactor.php`: `persist()`, `getSecretName()`.
- `src/Support/FactorStateTransaction.php`: `forIdentity()`, `forFactor()`.

## Authoritative Tests

- `tests/Unit/RecoveryCodes/BackupCodeDriverTest.php`
  `testIssueChallengeIsNoOp`
- `tests/Unit/RecoveryCodes/BackupCodeDriverTest.php`
  `testVerifyReturnsFalseWhenStoredSecretIsNull`
- `tests/Unit/RecoveryCodes/BackupCodeDriverTest.php`
  `testVerifyReturnsFalseWhenStoredSecretIsEmptyString`
- `tests/Unit/RecoveryCodes/BackupCodeDriverTest.php`
  `testVerifyReturnsFalseForWrongCodeHash`
- `tests/Unit/RecoveryCodes/BackupCodeDriverTest.php`
  `testVerifyReturnsTrueForNonEloquentFactorWithoutPersistence`
- `tests/Unit/RecoveryCodes/BackupCodeDriverTest.php`
  `testVerifyConsumesEloquentFactorAtomically`
- `tests/Unit/RecoveryCodes/BackupCodeDriverTest.php`
  `testVerifyReturnsFalseWhenConcurrentConsumeWinsFirst`
- `tests/Unit/RecoveryCodes/BackupCodeDriverTest.php`
  `testVerifyReturnsFalseWhenConcurrentConsumerDeletedTheRow`
- `tests/Unit/RecoveryCodes/BackupCodeDriverRaceTest.php`
  `testConsumeReturnsFalseWhenRowVanishes`
- `tests/Unit/RecoveryCodes/BackupCodeDriverGenerationTest.php`
  `testGenerateSetReturnsConfiguredNumberOfCodes`
- `tests/Unit/RecoveryCodes/BackupCodeDriverGenerationTest.php`
  `testGenerateSetReturnsDistinctCodes`
- `tests/Unit/RecoveryCodes/BackupCodeDriverGenerationTest.php`
  `testGenerateSetThrowsWhenExplicitCountIsZero`
- `tests/Unit/RecoveryCodes/BackupCodeDriverGenerationTest.php`
  `testHashIsDeterministicSha256`
- `tests/Unit/RecoveryCodes/RecoveryCodeServiceTest.php`
  `testReplacesOnlyTheIdentitysPreviousBatch`
- `tests/Unit/RecoveryCodes/RecoveryCodeServiceTest.php`
  `testAFailedRotationKeepsThePreviousBatch`
- `tests/Integration/Database/StorageConnectionRotationTest.php`

## Change Triggers

Update this note when any of the following change:

- the hashing algorithm, or the decision to hash rather than encrypt for backup codes
- the owner's lock + double-check pattern used to consume a code atomically
- the rule that enrolment is an atomic replace in the identity's factor state transaction
- the constant-time comparison on the candidate hash
- the decision to draw plaintext codes uniformly from the configured alphabet via `random_int`
- the rule that `secret` is encrypted at rest on the shipped factor model
