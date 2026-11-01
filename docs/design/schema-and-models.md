# Schema and Models

## Purpose

This note describes every table the package creates, the model each is read and written through, which models an
application may replace, the identity contract and its trait, and the one guard every operation on an identity's
factors starts with.

## Invariants

- Every table is named through `Database\TableNames` (`mfa.{block}.table`, defaulting to a name prefixed `mfa_`), lives
  on the storage connection (see [Storage and Transactions](storage-and-transactions.md)), and is keyed by a ULID,
  except the attempt throttles, which are keyed by a hash of what they count. Owners are plain string polymorphic
  columns, `authenticatable_type` and `authenticatable_id`, so integer, UUID and ULID identity keys all fit. The
  migrations run at deploy time; at runtime the package needs only `SELECT`, `INSERT`, `UPDATE` and `DELETE`.
- `mfa_factors`, one row per factor: owner, `type` (the name its driver is registered under), `label`, `destination`
  (SMS and email, captured at enrolment), `credential_reference` (passkey), `secret` (encrypted), the TOTP
  `totp_algorithm`, `totp_digits` and `totp_period` stored with the factor, `last_accepted_step`, `status` (`pending`
  until confirmed, by the table's default and the model's), `preferred`, the durable `consecutive_failures` and
  `disabled_at` of the failure ceiling, the `application` it was enrolled through, `confirmed_at` and `last_used_at`.
  A delivered code is never on the factor: it lives in `mfa_codes`. A successful verification is recorded as a proof
  on the session (see the proof store note), not on the factor.
- `mfa_identity_states`, one row per owner and the lock of every serialised change: `verification_generation`,
  `reenrollment_required`, the identity's `consecutive_failures` and `locked_until`, and `recovery_codes_generation`
  and `recovery_codes_generated_at`.
- `mfa_enrollments`, one row per enrolment in progress: the pending `factor_id` (unique), owner, the SHA-256
  `grant_hash` of its grant (unique), the `application` and `session_id` the grant is bound to, `expires_at` and its
  confirmation `attempts`.
- `mfa_codes`, one row per challenge of a code sent by SMS or email: `factor_id`, owner, the `purpose`, `application`
  and session the code is bound to (`session_id`, a keyed digest of the session's id), its keyed `code_hash`, the
  challenge's `attempts`, how many codes it was `sends`, the last `sent_at` and every send's time (`sent_times`),
  `expires_at` and `consumed_at` (see [Delivered Codes](delivered-codes.md)).
- `mfa_recovery_codes`: owner, the salted `code_hash`, the set's `generation`, `used_at` and `replaced_at`.
- `mfa_attempts`, the temporary throttles: `key` (a keyed hash of the scope and subject), `scope`, `hits` and
  `window_ends_at`. An identity's and an IP address's rows count failures within a window; a factor's row records the
  lockout its failures in a row applied, ending when its window does (see [Attempts and
  Lockout](attempts-and-lockout.md)).
- `mfa_passkey_associations`: the `factor_id` (unique), owner, and the credential by the SHA-256 `credential_id_hash`
  of its id (unique per owner) with the `credential_id` in full.
- No table holds a code, a recovery code or a grant in plaintext; the TOTP secret is encrypted by the model's cast.
  The factor model hides `secret`, `destination` and `credential_reference` from serialisation; the other models hide
  their hashes and session ids.
- Two models may be replaced through configuration: the factor model (`mfa.factor.model`, `Contracts\EloquentFactor`,
  through `Concerns\ActsAsFactor`) and the recovery code model (`mfa.recovery_codes.model`, `Contracts\RecoveryCode`,
  through `Concerns\ActsAsRecoveryCode`), resolved by `Database\ConfiguredModels`. Each exposes its columns through
  `get*Name()` methods so a model can remap one. The models of the other records (`Enrollment`, `Code`,
  `IdentityState`, `PasskeyAssociation`) are the package's own.
- A factor's status reads as pending unless the stored value says `confirmed`, so a missing or unknown value is never
  usable. `confirm()` marks it confirmed with its time; a verification stamps `last_used_at`.
- The identity contract, `Contracts\MultiFactorAuthenticatable`, asks whether the identity may hold factors
  (`canHoldFactors()`, people only), whether it is active (`isMfaActive()`) and what it requires of its own sign-ins
  (`requiresAdditionalFactor()`, a `Requirements\Requirement` or `null`). `Concerns\HasFactors` answers a person,
  active, requiring nothing, gives the factors of the configured model by the owner columns of its `authenticatable`
  relation, counts only a confirmed one as enabled (read from the write connection), and forgets the identity on the
  model's `deleted` event, once its row is gone, unless the delete was soft.
- `Lifecycle\ForgetIdentity` deletes the identity's codes, enrolments, passkey associations, recovery codes, factors and
  state row in its factor state transaction, by the owner columns of each model (a replaced factor or recovery code
  model's own relation columns). The attempt throttles are left to expire.
- `Factors\OperationGuard` is the first step of every operation on an identity's factors, refusing in this order: a
  machine (`machine_identity`), an inactive identity (`identity_inactive`), a factor not found within the identity
  (`not_found`, for another identity's id exactly as for one that does not exist), a pending factor where the
  operation needs a confirmed one (`not_confirmed`), and a type the application does not enable (`type_not_enabled`). A
  refusal throws `Exceptions\OperationRefusedException` with the reason. The factor is read from the write connection.

## Success Path

- An application publishes the migrations and runs them on the storage connection; a table it already has under a name
  stops the migration with the setting to change.
- An identity model implements the contract and uses `HasFactors`; it overrides `canHoldFactors()`, `isMfaActive()` or
  `requiresAdditionalFactor()` where its own state answers them.
- An operation resolves `OperationGuard`, calls `factor($identity, $id, $application)` (or `identity($identity)` before
  an operation on no factor) and acts on the factor it returns.

## Failure / Edge Cases

- A factor id that is neither a string nor an integer, or an identity whose key is neither, finds nothing.
- An inactive machine is refused as a machine: the reasons are checked in a fixed order.
- A model deleted without its events (a query builder `delete()`) is not forgotten by the trait; the application calls
  `ForgetIdentity` itself, as it does for an identity that is not an Eloquent model.
- A delete that a `deleting` listener cancels, or that fails, forgets nothing: the trait listens for `deleted`, so an
  identity is never left live without its factors. A soft delete forgets nothing; a force delete forgets the identity.
- The forgetting commits on its own after the delete, unless the delete runs in a transaction on the storage
  connection, which the forgetting then joins. A failure while forgetting an identity already deleted leaves records
  owned by an identity that no longer exists.
- Deleting an identity and a change racing it serialise on the identity's state row: a change already holding it
  commits first and is deleted with the rest. A change that takes it afterwards finds no factors; a record it then
  writes is owned by an identity that no longer exists.

## Implementation Anchors

- `database/migrations/`: one migration per table, each through `TableNames`, `IndexName` and `MigrationCollisionGuard`.
- `src/Models/`, `src/Concerns/ActsAsFactor.php`, `src/Concerns/ActsAsRecoveryCode.php`, `src/Concerns/HasFactors.php`.
- `src/Contracts/Factor.php`, `src/Contracts/EloquentFactor.php`, `src/Contracts/RecoveryCode.php`,
  `src/Contracts/MultiFactorAuthenticatable.php`.
- `src/Database/ConfiguredModels.php`, `src/Database/TableNames.php`.
- `src/Lifecycle/ForgetIdentity.php`, `src/Factors/OperationGuard.php`.

## Authoritative Tests

- `tests/Integration/MigrationSmokeTest.php`
- `tests/Unit/Factors/OperationGuardTest.php`
- `tests/Unit/Lifecycle/ForgetIdentityTest.php`
- `tests/Unit/Concerns/HasFactorsTest.php`, `tests/Unit/Concerns/ActsAsFactorStateTest.php`,
  `tests/Unit/Concerns/ActsAsRecoveryCodeTest.php`
- `tests/Unit/Models/FactorTest.php`, `tests/Unit/Models/StoredRecordModelsTest.php`
- `tests/Unit/Database/ConfiguredModelsTest.php`, `tests/Unit/Database/TableNamesTest.php`

## Change Triggers

- A new column or table: its migration, its model, this note and the configuration guide's table list.
- A column a later capability stops reading: it is dropped from the factors migration in place.
- A new check every operation needs: it joins `OperationGuard`, in a fixed place in its order.
