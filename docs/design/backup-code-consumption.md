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
- Consumption is therefore done under a pessimistic row lock: `lockForUpdate()` inside a transaction, double-check the
  hash against the locked row, null the secret column, commit.
- The transaction runs on the factor model's own database connection, not the container-default connection, so the
  atomicity guarantee survives consumers binding `config('mfa.factor.model')` to a model on a secondary connection.
- Hashing is SHA-256 rather than a slow password hash. Backup codes are already high-entropy random strings drawn
  uniformly from the configured alphabet via `random_int`; a password hash would add latency without meaningful extra
  security against credential stuffing.
- Verification of the candidate code against the stored hash uses `hash_equals` — constant-time comparison, closing
  the timing-oracle primitive.
- Enrolment is an atomic replace, not an append. `issueBackupCodes()` opens one transaction on the factor model's
  connection, deletes every existing `backup_code` row for the identity, inserts the freshly-minted batch, and returns
  the plaintext set exactly once. There is no window where both the old and new codes would verify.
- Non-Eloquent factors have no row to consume. The constant-time hash match alone is the verification result; consumers
  that ship a non-Eloquent factor implementation are responsible for their own single-use storage.

## Success Path

- The caller submits a plaintext code to `MfaManager::verify('backup_code', $factor, $code)`.
- `BackupCodeDriver::verify()` reads `$factor->getSecret()`, rejects null or empty secrets, and runs
  `hash_equals($stored, sha256($code))`.
- On a match against an Eloquent factor, the driver enters `consumeAtomic()`: opens a transaction on the factor's
  connection, re-reads the row under `lockForUpdate()`, rehashes the candidate against the locked row, writes `null`
  to the secret column, commits.
- The manager's `applyVerificationOutcome()` then runs `recordVerification()` on the factor (stamps `verified_at`,
  resets attempts, clears any pending code) and persists; `finaliseVerification()` writes the identity-level
  verification through the bound store and dispatches `MfaVerified`.
- A fresh batch via `issueBackupCodes()` deletes old rows, inserts new rows (each with the SHA-256 digest on
  `secret`), dispatches `MfaFactorEnrolled` once per new code, and returns the plaintext list to the caller.

## Failure / Edge Cases

- A wrong candidate fails the constant-time comparison before any lock is acquired. There is no row mutation and the
  manager increments the factor's attempt counter.
- Two concurrent requests submitting the same valid code race on `lockForUpdate()`. The winner consumes the row and
  returns `true`; the loser re-reads a secret that is now `null`, fails its second hash check, and returns `false`
  without mutating anything.
- If the row is deleted by a concurrent actor between the initial hash check and the lock, `find()` returns `null`
  inside the transaction and consumption returns `false`. The manager treats this as a verification failure with the
  standard classification.
- A stored `null` or empty secret short-circuits to `false` before the lock is acquired. This covers the already-
  consumed state and the stale-in-memory-but-cleared-in-DB state.
- `generateSet()` rejects a `$count` of zero or negative with `InvalidArgumentException`. Consumers cannot
  accidentally mint an empty batch that would still dispatch a rotation event with no replacement codes.
- Rotation runs inside a single transaction on the factor model's connection. A delete without an insert is not
  possible; a failure mid-rotation rolls back both, leaving the prior batch intact.

## Implementation Anchors

- `src/Drivers/BackupCodeDriver.php`: `verify()`, `consumeAtomic()`, `hash()`, `generateSecret()`,
  `generatePlaintextCode()`, `generateSet()`, `issueChallenge()` (no-op).
- `src/MfaManager.php`: `issueBackupCodes()`, `rotateBackupCodeBatch()`, `resolveDriver()`.
- `src/Models/Factor.php`: `secret` `encrypted` cast, `secret` included in `$hidden`.
- `src/Contracts/EloquentFactor.php`: `persist()`, `getSecretName()`, `getConnectionName()`.

## Authoritative Tests

- `tests/Unit/Drivers/BackupCodeDriverTest.php`
  `testIssueChallengeIsNoOp`
- `tests/Unit/Drivers/BackupCodeDriverTest.php`
  `testVerifyReturnsFalseWhenStoredSecretIsNull`
- `tests/Unit/Drivers/BackupCodeDriverTest.php`
  `testVerifyReturnsFalseWhenStoredSecretIsEmptyString`
- `tests/Unit/Drivers/BackupCodeDriverTest.php`
  `testVerifyReturnsFalseForWrongCodeHash`
- `tests/Unit/Drivers/BackupCodeDriverTest.php`
  `testVerifyReturnsTrueForNonEloquentFactorWithoutPersistence`
- `tests/Unit/Drivers/BackupCodeDriverTest.php`
  `testVerifyConsumesEloquentFactorAtomically`
- `tests/Unit/Drivers/BackupCodeDriverTest.php`
  `testVerifyReturnsFalseWhenConcurrentConsumeWinsFirst`
- `tests/Unit/Drivers/BackupCodeDriverTest.php`
  `testVerifyReturnsFalseWhenConcurrentConsumerDeletedTheRow`
- `tests/Unit/Drivers/BackupCodeDriverRaceTest.php`
  `testConsumeReturnsFalseWhenRowVanishes`
- `tests/Unit/Drivers/BackupCodeDriverGenerationTest.php`
  `testGenerateSetReturnsConfiguredNumberOfCodes`
- `tests/Unit/Drivers/BackupCodeDriverGenerationTest.php`
  `testGenerateSetReturnsDistinctCodes`
- `tests/Unit/Drivers/BackupCodeDriverGenerationTest.php`
  `testGenerateSetThrowsWhenExplicitCountIsZero`
- `tests/Unit/Drivers/BackupCodeDriverGenerationTest.php`
  `testHashIsDeterministicSha256`

## Change Triggers

Update this note when any of the following change:

- the hashing algorithm, or the decision to hash rather than encrypt for backup codes
- the `lockForUpdate()` + double-check pattern used to consume a code atomically
- the rule that enrolment is an atomic replace on the factor model's own connection
- the constant-time comparison on the candidate hash
- the decision to draw plaintext codes uniformly from the configured alphabet via `random_int`
- the rule that `secret` is encrypted at rest on the shipped factor model
