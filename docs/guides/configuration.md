# Configuration

The package's settings live in `config/mfa.php`, under the `mfa` key. Publish the file to change them:

```bash
php artisan vendor:publish --tag=mfa-config
```

## Storage

```php
'storage' => [
    'connection' => env('MFA_STORAGE_CONNECTION'),
],
```

Every table the package ships lives on `storage.connection`, the default connection when `null`: the factors and the
identity states. The shipped models read and write them there, and the published migrations create them there: each
names the storage connection as its own, so `php artisan migrate` creates every table where the package uses it,
whichever connection the migrator runs on. With `null`, the migrations follow the migrator, as any migration that names
no connection does, while the models use the default connection, so run them on the default connection. Laravel keeps
its `migrations` table on the migrator's connection either way.

The tables share one connection because the changes that depend on an identity's whole factor state (replacing its
recovery codes, removing a factor, a reset, a verification racing one of them) write several of them in one
transaction, which two connections cannot commit as one. Each such change locks the identity's row in the identity
states table first and its factors second, so two changes for one identity run one after the other. The factor model
must therefore live there too: the shipped `Models\Factor` takes the storage connection unless a subclass names a
connection of its own, and a factor model, shipped or custom, on any other connection fails with a
`ModelOffStorageConnectionException` when the package boots, rather than splitting a change across two transactions.
Connections are compared by name, a model's own or the default one, so two names for one database count as two
connections. Identity models may live on any connection: the shipped factor model always names the storage connection,
the default one included, so an identity's factor relation reads and writes the factors there rather than on the
identity's own connection. A custom factor model that names no connection of its own should do the same.

When the storage connection splits reads and writes (`read` and `write` hosts), the reads that decide a verification, a
lockout or who owns a factor go to the write host, so a replica that has not caught up cannot pass a used code or miss
a lockout.

A value that is neither a connection name nor `null` or empty fails closed with an `InvalidArgumentException` naming the
key. A model takes the connection when it is built, so keep the setting fixed while the application runs. Changing it
does not move tables already created, and a rollback runs against the setting at the time it runs: moving the tables is
a deploy, with a migration of your own that moves them and a restart of every worker.

## Table names

```php
'factor' => [
    'model' => env('MFA_FACTOR_MODEL', Factor::class),
    'table' => env('MFA_FACTOR_TABLE', 'mfa_factors'),
],

'identity_state' => [
    'table' => env('MFA_IDENTITY_STATE_TABLE', 'mfa_identity_states'),
],
```

`factor.table` names the factors table and `identity_state.table` the identity states table, which holds one row per
identity that owns factors. A long identity states table name is fine: its one-row-per-owner index is named after the
start of the table's name and a hash of the whole when the full name would pass the length an index name may have. Set
them before running the migrations: a migration whose table already exists on the storage connection stops with a
`TableAlreadyExistsException` naming the setting to change, before it changes anything. `factor.model` names the factor
model; see [Extending](extending.md).
