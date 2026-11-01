# Storage and Transactions

## Purpose

This note describes where the package's tables live, why they share one connection, and the one transaction and lock
order every change that depends on an identity's whole factor state runs in, so two such changes for one identity
cannot interleave.

## Invariants

- One resolver decides the connection, `Database\StorageConnection`: `name()` is `mfa.storage.connection`, `null` or
  empty for the default connection. A value that is neither a name nor `null` or empty fails closed with an
  `InvalidArgumentException` naming the key, rather than putting a table on another connection than the one meant.
- Every shipped model takes the storage connection when it is built (`StorageConnection::forModel()`), unless its class
  names a connection of its own, and always by name, the default connection included: Eloquent gives a related model
  that names no connection its parent's, so an identity on another connection would otherwise read and write its factors
  there, and the first serialised change for it would be refused. Every shipped migration's `getConnection()` returns
  the same value, and its collision guard, `create()` and `dropIfExists()` run on
  `Schema::connection($this->getConnection())`, so `php artisan migrate` puts each table where its model reads and
  writes it. With `null` the migrations name no connection and follow the migrator's.
- Every package table lives on the storage connection: the factors, identity states, enrolments, codes, recovery codes,
  attempts and passkey associations (see [Schema and models](schema-and-models.md)), each named through
  `Database\TableNames`. A change that depends on the identity's whole factor state writes several of them in one
  transaction, which two connections cannot commit as one, so a configured model on another connection is refused by the
  configuration check (`Config\ConfigurationValidator`, under its `factor` or `recovery_codes` subject) when the package
  boots and when the manager is resolved, and again (`ModelOffStorageConnectionException`) before any such change.
  Connections are compared by name, a model's own or `database.default`, so no connection is opened, and two names for
  one database count as two connections.
- `Support\FactorStateTransaction` is the one transaction of those changes: confirming an identity's first additional
  factor, replacing its recovery codes, removing a factor, a reset, and a verification racing any of them. It opens a
  transaction on the storage connection, locks the identity's row in `mfa_identity_states` first, then the identity's
  factors, read `FOR UPDATE` from the write connection, and hands the callback those factors as stored under the lock.
  Every change takes the locks in that order, so two changes for one identity never wait on each other in opposite
  orders: the second waits for the first to commit, then sees what it left, and checks its preconditions again on it.
- The identity's row is one per owner (a unique index on `authenticatable_type` and `authenticatable_id`), created by
  the first change that needs it. The lock is an insert that updates the existing row's `updated_at` on a conflict,
  which takes the row's exclusive lock in one statement on MySQL and PostgreSQL, also when two first changes race to
  create it. A separate insert and `SELECT ... FOR UPDATE` would let two transactions share a lock on MySQL and then
  deadlock upgrading it. SQLite serialises its writers, so the insert takes the database's write lock there.
- Reads that decide a verification, a lockout or who owns a factor go to the storage connection's write host
  (`Database\WriteConnection::query()`), so a replica that lags behind a lockout, a used code or a removed factor
  cannot answer them: the identity's factors as `FactorService::getFactors()` reads them, whether the identity has a
  confirmed factor as `HasFactors::isMfaEnabled()` reads it (and so `Mfa::isSetup()`), and every read inside
  `FactorStateTransaction`, which locks its rows and so reads from the writer anyway. A factor the application loads
  itself and hands in is read wherever the application read it.
- Every index a shipped migration names (`Database\IndexName`) is the table's name and a suffix, such as
  `{table}_owner_unique`, or, when that would pass 63 characters (PostgreSQL's limit; MySQL's is 64), the start of the
  table's name, a hash of the whole and the same suffix, so a long configured table name still migrates and the name is
  the same on every run.
- The owner is recorded as on the factors table: its morph class for an Eloquent identity (honouring the morph map), its
  class name otherwise, and its key as a string. Its columns are read from the owner relation of a blank instance of the
  factor's class (`Support\FactorOwnerColumns`), never of a stored factor, on which Eloquent would build the owner: an
  owner that is not an Eloquent model cannot be built, and is locked and matched by its columns all the same. A key that
  is neither a non-empty string nor an integer is refused (`UnsupportedIdentifierException`) rather than collapsing
  distinct identities onto one lock.
- Calls to another package that must be atomic with the change (revoking sessions, reporting a challenge's outcome, a
  passkey change gate) run inside the callback. An adapter whose own storage is on another connection cannot be atomic
  with it and must say so.
- Backup codes already run on it: `issueBackupCodes()` replaces the batch inside the transaction, and the backup-code
  driver consumes a code inside the owner's transaction, comparing it again as stored under the lock.

## Success Path

- With `mfa.storage.connection` `null`, every model and table is on the default connection; run the migrations on it.
- With it set, `php artisan migrate` creates the package's tables on that connection, the shipped models read and
  write them there, and `FactorStateTransaction` opens its transactions there. A custom factor model names that
  connection, or names none and extends the shipped model, which then follows it.
- A change calls `FactorStateTransaction::forIdentity($identity, new $factorModel, $callback)`, or `forFactor($factor,
  $callback)` for the factor's owner. Inside, the callback reads what it decides on from the factors it is handed,
  writes, and returns its answer, which the transaction passes back once it commits.

## Failure / Edge Cases

- A model on another connection fails when the package boots, before it serves a request, and `FactorStateTransaction`
  refuses it again before opening a transaction, so a configuration changed after boot (in a test) cannot split a
  change across two connections either. A configured factor model that is not a factor model at all fails at boot too.
- A callback that throws rolls the whole change back, releases both locks and leaves nothing it wrote, the identity's
  first state row included. The exception reaches the caller unchanged.
- A change nested inside another transaction on the storage connection becomes a savepoint of it: the locks are held
  until the outer transaction ends.
- Changing the setting moves no table, and a rollback runs against the setting at the time it runs: moving the tables
  is a deploy, with a migration the application writes and a restart of every worker.

## Implementation Anchors

- `src/Database/StorageConnection.php`: `name()`, `resolvedName()`, `nameOf()`, `assertHolds()`.
- `src/Config/ConfigurationValidator.php`: `checkModel()`, `checkStorageConnection()`, `checkDistinctTables()`.
- `src/Database/TableNames.php`, `src/Database/IndexName.php`.
- `src/Database/WriteConnection.php`: `query()`; `src/Factors/FactorService.php`: `getFactors()`.
- `src/Support/FactorStateTransaction.php`: `forIdentity()`, `forFactor()`, the lock order in `run()`;
  `src/Support/FactorOwnerColumns.php`: `of()`.
- The constructor of every model under `src/Models/`; `getConnection()` in every migration under `database/migrations/`.
- `src/RecoveryCodes/RecoveryCodeService.php`: `issueBackupCodes()`; `src/RecoveryCodes/BackupCodeDriver.php`:
  `consumeAtomic()`.

## Authoritative Tests

- `tests/Integration/Database/FactorStateLockTest.php`
- `tests/Integration/Database/StorageConnectionRotationTest.php`
- `tests/Integration/Database/IdentityOffStorageConnectionTest.php`
- `tests/Integration/Database/WriteConnectionReadTest.php`
- `tests/Unit/Database/WriteConnectionTest.php`
- `tests/Unit/Support/FactorOwnerColumnsTest.php`
- `tests/Unit/Support/FactorStateTransactionTest.php`
- `tests/Unit/Database/StorageConnectionTest.php`
- `tests/Unit/Config/ConfigurationValidatorTest.php` `testAFactorModelOnTheStorageConnectionHasNoProblem`
- `tests/Unit/Models/FactorTest.php` `testTakesTheStorageConnection`, `testKeepsAConnectionTheClassNames`
- `tests/Integration/MigrationSmokeTest.php` `testIdentityStatesTableHasOneRowPerOwner`,
  `testALongIdentityStatesTableNameGivesAShortOwnerIndexName`
- `tests/Unit/Models/StoredRecordModelsTest.php` `testTakesTheStorageConnection`
- `tests/Unit/Database/TableNamesTest.php`, `tests/Unit/Database/IndexNameTest.php`

## Change Triggers

- A new package table: its model and its migration take the resolver, and `ConfigurationValidator` checks its model.
- A new change that depends on the identity's whole factor state: it runs in `FactorStateTransaction`.
- Any change to the lock order, to how the identity's row is locked, or to how connections are compared.
- A new read that decides a verification, a lockout or ownership outside `FactorStateTransaction`: it goes through
  `WriteConnection`.
