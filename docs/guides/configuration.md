# Configuration

The package's settings live in `config/mfa.php`, under the `mfa` key. Publish the file to change them:

```bash
php artisan vendor:publish --tag=mfa-config
```

Each capability has a block of its own, and each application a block under `applications`. A value that is malformed or
out of its bounds fails closed with an `InvalidArgumentException` naming the key; it is never clamped or replaced with a
default. The whole configuration, with the bindings it needs, is checked once the application has booted and again when
the `mfa` manager is resolved, so a misconfiguration fails before anyone verifies a factor (see
[Checking the configuration](#checking-the-configuration)). Settings are read each time they are used, never cached
between requests.

| Key                             | Default                            | Bounds                                 | Env                                 | Applied |
|---------------------------------|------------------------------------|----------------------------------------|-------------------------------------|---------|
| `applications`                  | `[]`                               | see [Applications](#applications)      |                                     | not yet |
| `storage.connection`            | `null`                             | a configured connection, or `null`     | `MFA_STORAGE_CONNECTION`            | yes     |
| `factor.model`                  | `Models\Factor`                    | an Eloquent `EloquentFactor` model     | `MFA_FACTOR_MODEL`                  | yes     |
| `factor.table`                  | `mfa_factors`                      | a table name                           | `MFA_FACTOR_TABLE`                  | yes     |
| `identity_state.table`          | `mfa_identity_states`              | a table name                           | `MFA_IDENTITY_STATE_TABLE`          | yes     |
| `enrollment.table`              | `mfa_enrollments`                  | a table name                           | `MFA_ENROLLMENT_TABLE`              | yes     |
| `codes.table`                   | `mfa_codes`                        | a table name                           | `MFA_CODES_TABLE`                   | yes     |
| `recovery_codes.model`          | `Models\RecoveryCode`              | an Eloquent `RecoveryCode` model       | `MFA_RECOVERY_CODES_MODEL`          | yes     |
| `recovery_codes.table`          | `mfa_recovery_codes`               | a table name                           | `MFA_RECOVERY_CODES_TABLE`          | yes     |
| `attempts.table`                | `mfa_attempts`                     | a table name                           | `MFA_ATTEMPTS_TABLE`                | yes     |
| `passkeys.table`                | `mfa_passkey_associations`         | a table name                           | `MFA_PASSKEYS_TABLE`                | yes     |
| `totp.algorithm`                | `sha1`                             | `sha1`, `sha256`, `sha512`             | `MFA_TOTP_ALGORITHM`                | not yet |
| `totp.digits`                   | `6`                                | 6 to 8                                 | `MFA_TOTP_DIGITS`                   | not yet |
| `totp.period`                   | `30`                               | 15 to 120 seconds                      | `MFA_TOTP_PERIOD`                   | not yet |
| `totp.window`                   | `1`                                | 0 to 3 steps                           | `MFA_TOTP_WINDOW`                   | yes     |
| `codes.length`                  | `6`                                | 6 to 10 digits                         | `MFA_CODES_LENGTH`                  | yes     |
| `codes.ttl_minutes`             | `10`                               | 1 to 10 minutes                        | `MFA_CODES_TTL_MINUTES`             | yes     |
| `codes.resend_cooldown_seconds` | `60`                               | 0 to the code lifetime                 | `MFA_CODES_RESEND_COOLDOWN_SECONDS` | not yet |
| `codes.factor_send_limit`       | `5`                                | 1 to 50                                | `MFA_CODES_FACTOR_SEND_LIMIT`       | not yet |
| `codes.identity_send_limit`     | `10`                               | 1 to 100                               | `MFA_CODES_IDENTITY_SEND_LIMIT`     | not yet |
| `codes.send_window_minutes`     | `60`                               | 1 to 1440 minutes                      | `MFA_CODES_SEND_WINDOW_MINUTES`     | not yet |
| `codes.sms_message`             | `Your verification code is: :code` | carries `:code`                        | `MFA_CODES_SMS_MESSAGE`             | yes     |
| `codes.mailable`                | `Codes\MfaCodeMessage`             | `MfaCodeMessage` or a subclass         |                                     | yes     |
| `recovery_codes.count`          | `10`                               | 1 to 50                                | `MFA_RECOVERY_CODES_COUNT`          | yes     |
| `recovery_codes.length`         | `12`                               | 1 to 64, and 40 bits with the alphabet | `MFA_RECOVERY_CODES_LENGTH`         | yes     |
| `recovery_codes.alphabet`       | `23456789ABCDEFGHJKLMNPQRSTUVWXYZ` | see [Recovery codes](#recovery-codes)  | `MFA_RECOVERY_CODES_ALPHABET`       | yes     |
| `recovery_codes.low_count`      | `3`                                | 0 to the set's size                    | `MFA_RECOVERY_CODES_LOW_COUNT`      | not yet |
| `attempts.factor_limit`         | `5`                                | 1 to 20                                | `MFA_ATTEMPTS_FACTOR_LIMIT`         | yes     |
| `attempts.identity_limit`       | `20`                               | 1 to 100                               | `MFA_ATTEMPTS_IDENTITY_LIMIT`       | not yet |
| `attempts.ip_limit`             | `100`                              | 1 to 10000                             | `MFA_ATTEMPTS_IP_LIMIT`             | not yet |
| `attempts.window_seconds`       | `900`                              | 60 to 86400 seconds                    | `MFA_ATTEMPTS_WINDOW_SECONDS`       | not yet |
| `attempts.lockout_seconds`      | `900`                              | 60 to 86400 seconds                    | `MFA_ATTEMPTS_LOCKOUT_SECONDS`      | yes     |
| `attempts.failure_ceiling`      | `100`                              | 1 to 100                               | `MFA_ATTEMPTS_FAILURE_CEILING`      | not yet |
| `enrollment.ttl_minutes`        | `15`                               | 1 to 60 minutes                        | `MFA_ENROLLMENT_TTL_MINUTES`        | not yet |
| `proofs.max_age_minutes`        | `20160`                            | 0 to 525600 minutes                    | `MFA_PROOFS_MAX_AGE_MINUTES`        | yes     |
| `lifecycle.prune_after_days`    | `30`                               | 1 to 3650 days                         | `MFA_LIFECYCLE_PRUNE_AFTER_DAYS`    | not yet |

Every class name is relative to `SineMacula\Laravel\Mfa`. Numbers may be integers or the digit strings `env()` returns;
anything else, a sign, padding, a fraction or an exponent included, is refused.

**Applied** says whether anything reads the setting yet. A setting marked *not yet* is checked with the rest, so a
deployment can set it now and a bad value still fails, but no flow applies it: setting it changes nothing until the
flow that reads it ships. Do not rely on one for protection in the meantime.

## Applications

An application is the app being signed into: an admin web app, a mobile app. Without an authentication layer that names
it, the application is the name of the guard that authenticated the request. Factors, the recovery code set, attempt
state and lockouts belong to the identity and are the same in every application; what an application chooses is what it
accepts and offers, and its limits on enrolments made through it. Each has a block under `applications`, keyed by its
name:

```php
'applications' => [
    'web' => [
        'types'          => ['totp', 'email'],
        'requirement'    => 'enrolled',
        'recovery_codes' => ['enabled' => true, 'level' => 'aal2'],
        'bootstrap'      => ['enabled' => true, 'types' => ['totp']],
        'limits'         => ['confirmed_per_type' => 3, 'confirmed' => 6, 'pending' => 1],
        'totp_window'    => 1,
        'freshness'      => ['mfa.remove_factor' => 300, 'billing.change_plan' => 600],
        'first_factor'   => ['method' => 'password', 'channel' => 'password'],
    ],
],
```

No flow reads an application's block yet: every key below is checked, but none is applied. Until the flows that read
them ship, the shipped drivers verify a factor of any type whichever application asks, no factor is required by this
configuration alone, the TOTP driver accepts `totp.window` steps for every application, and the limits and freshness
are not enforced. Use your own policy binding (`Contracts\MfaPolicy`) and routes to decide who must verify.

| Key                         | Default                   | Meaning                                                                                                                                |
|-----------------------------|---------------------------|----------------------------------------------------------------------------------------------------------------------------------------|
| `types`                     | `[]`                      | The factor types the application enables, by driver name; none is on until listed                                                      |
| `requirement`               | `never`                   | When an additional factor is required: `never`, `enrolled` (once the identity has a confirmed factor, which is optional MFA), `always` |
| `recovery_codes.enabled`    | `false`                   | Whether the application accepts recovery codes                                                                                         |
| `recovery_codes.level`      | `aal2`                    | The assurance level a session needs to be issued recovery codes: `aal1`, `aal2` or `aal3`                                              |
| `bootstrap.enabled`         | `false`                   | Whether a pending session with no factor may enrol its first one                                                                       |
| `bootstrap.types`           | `[]`                      | The types it may enrol: types the application enables, at least one while bootstrap is on                                              |
| `limits.confirmed_per_type` | `5`, at most the total    | Confirmed factors of one type an identity may enrol through the application, 1 to `limits.confirmed`                                   |
| `limits.confirmed`          | `10`                      | Confirmed factors an identity may enrol through the application in total, 1 to 50                                                      |
| `limits.pending`            | `2`                       | Enrolments an identity may have pending through the application at once, 1 to 10                                                       |
| `totp_window`               | `totp.window`             | TOTP time steps accepted either side of the current one, 0 to 3                                                                        |
| `freshness`                 | 900 seconds per operation | How fresh a proof must be for each named operation, 1 to 86400 seconds                                                                 |
| `first_factor`              | `null`                    | The first factor the application's guard signs people in with: a `method` and the `channel` kind it proves                             |

An application with no block, and one whose block leaves a key out or sets it to `null`, takes the defaults: no type, no
requirement, no recovery codes and no bootstrap, so once the flows apply the block a name nobody configured enables
nothing. Left unset, `limits.confirmed_per_type` is 5, or `limits.confirmed` when that is lower; set explicitly above
it, it is refused. A key the block does not know, in it or in one of its nested blocks, is refused rather than ignored,
so a misspelt key cannot leave a setting at its default unnoticed, and an `applications` value that is not an array is
refused too.

`limits` count only the enrolments made through the application: a factor enrolled through another counts against that
application's limits, never this one's, and an application never removes, hides or changes a factor enrolled through
another.

`freshness` names the maximum age, in seconds, of the proof that satisfies each operation's step-up. The package's own
operations (`mfa.add_factor`, `mfa.replace_factor`, `mfa.remove_factor` and `mfa.generate_recovery_codes`) default to
900 seconds; an application overrides them and adds its own operations by name. An operation neither names is never
fresh.

`first_factor` is how the package knows, without an authentication layer, what started the sign-in: its `method` (any
name, such as `password`) and its `channel`, one of the channel kinds (`password`, `sms`, `email`,
`authenticator_app`, `passkey`, `external_provider`). An unknown first factor accepts no further factor and establishes
no level, so every configured application must either declare one or have a `Contracts\FirstFactorResolver` bound,
which an authentication layer's adapter provides; with neither, the configuration check fails. The channel `unknown`
is refused, as it declares nothing.

Each code type an application enables needs something to deliver its codes: `sms` a `Contracts\SmsGateway` other than
the package's `NullSmsGateway`, and `email` a mailer bound in the container (looked up, not built, so the check builds
no mail transport). Enabling one without it fails the configuration check, rather than the first send. A binding the
container cannot build, such as a gateway bound to a class that does not exist, is reported under the application too.

## Storage

```php
'storage' => [
    'connection' => env('MFA_STORAGE_CONNECTION'),
],
```

Every table the package ships lives on `storage.connection`, the default connection when `null`: the factors, the
identity states, the enrolments in progress, the delivered codes, the recovery codes, the attempt throttles and the
passkey associations. The shipped models read and write them there, and the published migrations create them there: each
names the storage connection as its own, so `php artisan migrate` creates every table where the package uses it,
whichever connection the migrator runs on. With `null`, the migrations follow the migrator, as any migration that names
no connection does, while the models use the default connection, so run them on the default connection. Laravel keeps
its `migrations` table on the migrator's connection either way.

The tables share one connection because the changes that depend on an identity's whole factor state (replacing its
recovery codes, removing a factor, a reset, a verification racing one of them) write several of them in one
transaction, which two connections cannot commit as one. Each such change locks the identity's row in the identity
states table first and its factors second, so two changes for one identity run one after the other. The factor model
must therefore live there too: the shipped models take the storage connection unless a subclass names a connection of
its own, and a factor or recovery code model, shipped or custom, on any other connection fails the configuration check
when the package boots, and with a `ModelOffStorageConnectionException` before any such change opens its transaction,
rather than splitting a change across two transactions.
Connections are compared by name, a model's own or the default one, so two names for one database count as two
connections. Identity models may live on any connection: the shipped factor model always names the storage connection,
the default one included, so an identity's factor relation reads and writes the factors there rather than on the
identity's own connection. A custom factor model that names no connection of its own should do the same.

When the storage connection splits reads and writes (`read` and `write` hosts), the reads that decide a verification, a
lockout or who owns a factor go to the write host, so a replica that has not caught up cannot pass a used code or miss
a lockout.

A value that is neither a connection name nor `null` or empty fails closed with an `InvalidArgumentException` naming the
key, and a name `database.connections` does not configure fails the configuration check. A model takes the connection
when it is built, so keep the setting fixed while the application runs. Changing it does not move tables already
created, and a rollback runs against the setting at the time it runs: moving the tables is a deploy, with a migration of
your own that moves them and a restart of every worker.

## Table names and models

```php
'factor' => [
    'model' => env('MFA_FACTOR_MODEL', Factor::class),
    'table' => env('MFA_FACTOR_TABLE', 'mfa_factors'),
],

'identity_state' => [
    'table' => env('MFA_IDENTITY_STATE_TABLE', 'mfa_identity_states'),
],

'recovery_codes' => [
    'model' => env('MFA_RECOVERY_CODES_MODEL', RecoveryCode::class),
    'table' => env('MFA_RECOVERY_CODES_TABLE', 'mfa_recovery_codes'),
    // ...
],
```

Every table the package creates is named in its capability's block and defaults to a name prefixed `mfa_`:

| Setting                | Default                    | Holds                                                                                |
|------------------------|----------------------------|--------------------------------------------------------------------------------------|
| `factor.table`         | `mfa_factors`              | One row per factor, pending or confirmed                                             |
| `identity_state.table` | `mfa_identity_states`      | One row per identity that owns factors: its generation, obligation and failures      |
| `enrollment.table`     | `mfa_enrollments`          | One row per enrolment in progress: its pending factor and the hash of its grant      |
| `codes.table`          | `mfa_codes`                | The codes sent by SMS or email, as keyed hashes bound to factor, purpose and session |
| `recovery_codes.table` | `mfa_recovery_codes`       | Each identity's recovery codes, as salted hashes                                     |
| `attempts.table`       | `mfa_attempts`             | The temporary attempt throttles, one counter per scope and subject                   |
| `passkeys.table`       | `mfa_passkey_associations` | Which passkeys are associated with an identity as factors                            |

[Schema and models](../design/schema-and-models.md) describes every column. Long names are fine: an index is named
after the start of its table's name and a hash of the whole when the full name would pass the length an index name may
have. Set the names before running the migrations: a migration whose table already exists on the storage connection
stops with a `TableAlreadyExistsException` naming the setting to change, before it changes anything. A table name that
is not a non-blank string, or two tables sharing a name, fail the configuration check.

`factor.model` and `recovery_codes.model` name the factor and recovery code models, which an application may replace
with a subclass of the shipped one or its own Eloquent model implementing `Contracts\EloquentFactor` or
`Contracts\RecoveryCode` (the `ActsAsFactor` and `ActsAsRecoveryCode` traits do); see [Extending](extending.md). A model
that is not one fails the configuration check. The package's other records use models of its own, which are not
replaced.

## TOTP

```php
'totp' => [
    'algorithm' => env('MFA_TOTP_ALGORITHM', 'sha1'),
    'digits'    => env('MFA_TOTP_DIGITS', 6),
    'period'    => env('MFA_TOTP_PERIOD', 30),
    'window'    => env('MFA_TOTP_WINDOW', 1),
],
```

`algorithm`, `digits` and `period` are the parameters new TOTP enrolments will use; the defaults (SHA-1, 6 digits, 30
seconds) are what authenticator apps expect, and they are what the TOTP driver uses today whatever is set, as these
three are not applied yet. A period is at most 120 seconds. `window` is the number of time steps either side of
the current one a code is accepted for, absorbing clock skew and entry delay, for an application that sets no
`totp_window` of its own. It is at most 3; the default of 1 follows RFC 6238, which recommends allowing at most one step
for transmission delay.

## Delivered codes

```php
'codes' => [
    'length'                  => env('MFA_CODES_LENGTH', 6),
    'ttl_minutes'             => env('MFA_CODES_TTL_MINUTES', 10),
    'resend_cooldown_seconds' => env('MFA_CODES_RESEND_COOLDOWN_SECONDS', 60),
    'factor_send_limit'       => env('MFA_CODES_FACTOR_SEND_LIMIT', 5),
    'identity_send_limit'     => env('MFA_CODES_IDENTITY_SEND_LIMIT', 10),
    'send_window_minutes'     => env('MFA_CODES_SEND_WINDOW_MINUTES', 60),
    'sms_message'             => env('MFA_CODES_SMS_MESSAGE', 'Your verification code is: :code'),
    'mailable'                => MfaCodeMessage::class,
],
```

A code sent by SMS or email has `length` digits, at least 6, and works for `ttl_minutes` after it is sent, at most 10.
`resend_cooldown_seconds` is how long after a code is sent another may be sent to the same factor, never longer than the
code's lifetime, and `factor_send_limit` and `identity_send_limit` cap how many one factor and one identity, across its
factors and sessions, are sent within `send_window_minutes`; these four are checked but not applied yet, so nothing
limits sending until the flow that applies them ships. `sms_message` is the SMS text, which must carry the `:code`
placeholder the code replaces, and `mailable` the email message class, `Codes\MfaCodeMessage` or a subclass of it.

## Recovery codes

```php
'recovery_codes' => [
    'count'     => env('MFA_RECOVERY_CODES_COUNT', 10),
    'length'    => env('MFA_RECOVERY_CODES_LENGTH', 12),
    'alphabet'  => env('MFA_RECOVERY_CODES_ALPHABET', '23456789ABCDEFGHJKLMNPQRSTUVWXYZ'),
    'low_count' => env('MFA_RECOVERY_CODES_LOW_COUNT', 3),
],
```

A set holds `count` codes of `length` characters drawn from `alphabet`. A code is normalised before it is checked: case
is folded, and spaces and hyphens are removed. Its entropy is therefore measured on what is left, as the length times
the bits of each character, and it must be at least 40 bits. The default, 12 characters from 32 (digits and capitals
without `0`, `1`, `I` and `O`), gives 60. The alphabet is at least two printable ASCII characters, without spaces or
hyphens, which normalisation would remove, and no character may appear twice, counting two that differ only in case as
the same: a repeated character would be drawn more often than the others, so the codes would carry less entropy than the
measure says. `low_count` is how few unused codes count as running low, from 0 (never) to the set's size; left unset it
is 3, or the set's size when that is smaller. It is checked but not applied yet.

## Attempts

```php
'attempts' => [
    'factor_limit'    => env('MFA_ATTEMPTS_FACTOR_LIMIT', 5),
    'identity_limit'  => env('MFA_ATTEMPTS_IDENTITY_LIMIT', 20),
    'ip_limit'        => env('MFA_ATTEMPTS_IP_LIMIT', 100),
    'window_seconds'  => env('MFA_ATTEMPTS_WINDOW_SECONDS', 900),
    'lockout_seconds' => env('MFA_ATTEMPTS_LOCKOUT_SECONDS', 900),
    'failure_ceiling' => env('MFA_ATTEMPTS_FAILURE_CEILING', 100),
],
```

`factor_limit` failed attempts in a row lock a factor, of any type, for `lockout_seconds`. These two are applied today.
`identity_limit` failed attempts across an identity's factors and recovery codes, and `ip_limit` from one IP address,
within `window_seconds`, are to lock the identity and throttle the address, and `failure_ceiling` consecutive failures
are to disable a factor until the person proves another, it is rebound or the identity is reset; it is at most 100, the
most NIST SP 800-63B-4 allows. These four are checked but not applied yet: until they are, only the per-factor lockout
limits guessing.

## Enrolment

```php
'enrollment' => [
    'ttl_minutes' => env('MFA_ENROLLMENT_TTL_MINUTES', 15),
],
```

A pending factor is to be confirmable for `ttl_minutes` after its enrolment starts, at most 60, and abandoned after
that. It is checked but not applied yet.

## Proofs

```php
'proofs' => [
    'max_age_minutes' => env('MFA_PROOFS_MAX_AGE_MINUTES', 20160),
],
```

`max_age_minutes` is how long a recorded verification counts before the person must verify again, 14 days by default
and at most a year: the `mfa` middleware's window when the route gives none, judged on the newest factor or recovery
code proof of the current sign-in (see [Recorded proofs](proofs.md)). With `0` none counts, so the `mfa` middleware
refuses every request; use its step-up parameter to require a fresh verification for one route group instead.

## Lifecycle

```php
'lifecycle' => [
    'prune_after_days' => env('MFA_LIFECYCLE_PRUNE_AFTER_DAYS', 30),
],
```

`prune_after_days` is how long pruning is to keep abandoned enrolments, expired codes, and used or replaced recovery
codes after they stop being usable. It is checked but not applied yet: the package prunes nothing so far.

## Checking the configuration

The package checks its whole configuration, with the bindings it needs, once the application has booted (after every
service provider, so a binding made in a provider's `boot()` counts) and again when the `mfa` manager is resolved. Any
problem fails with an `Exceptions\InvalidConfigurationException` whose message, and whose `problems`, list every problem
found, each as `[<subject>] <message>`. The subjects are `storage`, `factor`, `identity_state`, each capability block
(`totp`, `codes`, `recovery_codes`, `attempts`, `enrollment`, `proofs`, `lifecycle`), `applications`, and
`applications.<name>` for each configured application, whose problems include a code type with no delivery binding and
a first factor neither declared nor resolved.

Run the same check from a deploy pipeline or a readiness probe:

```bash
php artisan mfa:check
```

It prints `[<subject>] OK` for each subject without a problem and each problem as an error, and exits `1` when there is
one. The boot check is skipped while `mfa:check` runs, behind any option (`php artisan -v mfa:check`), so the command
reports the problems rather than failing on the first. It is skipped too while `config:cache`, `config:clear`,
`config:show`, `optimize:clear`, `package:discover`, `list` or `help` runs, so a bad configuration, a cached one
included, can still be inspected and cleared; resolving the `mfa` manager checks it whatever command runs. It reads
configuration and the container only, and opens no database connection.
