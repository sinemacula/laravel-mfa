# Application Configuration

## Purpose

This note describes how the package's configuration is shaped and read: one block per application for what that
application accepts and offers, one block per capability for what is the same everywhere, each read through a settings
class that checks it as it reads it, and the check of the whole configuration, with the bindings it needs, that runs
before anything relies on it.

## Invariants

- Factors, the recovery code set, attempt state and lockouts belong to the identity and are the same in every
  application. What varies per application is only what it accepts and offers: the factor types it enables, when it
  requires a factor, whether it accepts recovery codes and at what level it issues them, whether a pending session may
  enrol its first factor, its limits on enrolments made through it, its TOTP window, the requirement of each operation's
  step-up, and the first factor its guard uses. Those live in `mfa.applications.{name}`; everything else lives in a
  block per capability (`totp`, `codes`, `recovery_codes`, `attempts`, `enrollment`, `proofs`, `lifecycle`) beside
  `storage`, `factor` and `identity_state`.
- Not every setting is applied yet. Of an application block, `totp_window` is read by the TOTP driver for the
  application a bound `ApplicationResolver` names, `recovery_codes.enabled` by the recovery code service, `requirement`
  by `Mfa::requirement()` and `freshness` by `Mfa::isFresh()` (see
  [Requirements and Freshness](requirements-and-freshness.md)); otherwise nothing is enforced per application: the
  shipped drivers verify any type, and the limits are not applied. Of the package-wide blocks, the code resend cooldown
  and send caps, the enrolment lifetime and the pruning retention are checked only. The configuration guide marks each
  setting as applied or not, and a flow that starts reading one updates it.
- Every setting is read through one class that owns its block: `Applications\ApplicationSettings` (with
  `Applications\ApplicationBlock` reading the raw block), `Drivers\TotpSettings`, `Codes\CodeSettings`,
  `RecoveryCodes\RecoveryCodeSettings`, `Attempts\AttemptSettings`, `Enrollment\EnrollmentSettings`,
  `Proofs\ProofSettings` and `Lifecycle\LifecycleSettings`. Each reads the configuration on every call and holds nothing
  between calls, so no request's settings outlive it in a long-running process, and a change applies at once.
- A setting is checked as it is read. A number is an integer, or the digit string `env()` returns for one, within its
  bounds (`Config\IntegerSetting`); anything else, and anything out of bounds, fails closed with an
  `InvalidArgumentException` naming the key and the bounds. Nothing is clamped, and nothing malformed falls back to a
  default: a value that cannot be read is a deployment error, not a reason to grant a wider window. A default whose
  bound is another setting follows that setting down when left unset (`limits.confirmed_per_type` at most
  `limits.confirmed`, `recovery_codes.low_count` at most `recovery_codes.count`), so a key nobody set never fails; a
  value set explicitly past the bound is refused.
- The bounds the specifications set are enforced: delivered codes have at least 6 digits and live at most 10 minutes;
  a TOTP period is at most 120 seconds and the window at most 3 steps; the failure ceiling is at most 100; a recovery
  code carries at least `RecoveryCodeSettings::MINIMUM_ENTROPY_BITS` (40) bits measured after normalisation (case
  folded, spaces and hyphens removed). The measure is the length times the bits of each alphabet character, which
  holds because the alphabet repeats no character once case is folded: a repeated one would be drawn more often, and
  the codes would carry less than the measure says. Every default sits inside its bounds.
- A key missing from an application block, or set to `null`, takes the production-safe default: no type enabled,
  `never` required, no recovery codes, no bootstrap. An application with no block takes them all, so once the flows
  read the block a name nobody configured enables nothing. A key an application block, or one of its nested blocks,
  does not know is refused rather than ignored, and so is an `mfa.applications` that is not an array, by every reader
  rather than only by the check.
- An application declares the first factor its guard uses (a method and a channel kind other than `unknown`), or a
  `Contracts\FirstFactorResolver` is bound to report it. A configured application with neither is a misconfiguration:
  an unknown first factor accepts no further factor and establishes no level.
- A code type an application enables has something to deliver its codes: `sms` a `Contracts\SmsSender` other than the
  package's `NullSmsSender`, `email` a `Contracts\EmailSender` other than its `NullEmailSender`; and either has the
  application key its codes are hashed with (see [Delivered Codes](delivered-codes.md)). The package's
  `MailEmailSender` looks its mailer up only to send, so the boot check of every request builds no mail transport.
- `Config\ConfigurationValidator` runs every check and groups the problems by subject: `storage`, `factor`,
  `identity_state`, each capability block, `applications`, and `applications.{name}`. It runs once the application has
  booted (`Config\ConfigurationBindings::boot()`, from the provider's `boot()`, deferred until every provider has
  booted) and again from the `mfa` manager's factory before the manager is built. Either throws an
  `Exceptions\InvalidConfigurationException` listing every problem. A binding the container cannot build is a problem
  of the subject that needs it, not an escape from the report. It reads configuration and the container only and opens
  no database connection. The storage checks (the connection, and the factor model on it) are part of it, so
  `mfa:check` reports them like any other problem.
- The boot check is skipped while `mfa:check` runs, found as the console finds a command (the first argument that is
  not an option), and while `config:cache`, `config:clear`, `config:show`, `optimize:clear`, `package:discover`,
  `list` or `help` runs, so a bad configuration, a cached one included, can be inspected and cleared. The manager's
  factory checks whatever runs.
- The drivers take their settings as given: the shipped ones are built from the settings classes, so their
  constructors check nothing themselves.

## Success Path

- The shipped configuration has no problem: every block takes its defaults and no application is configured.
- An application is configured under its name with the types it enables and its first factor; the boot check passes,
  and every later read of its settings returns what it configures.
- `php artisan mfa:check` prints `[<subject>] OK` for each subject and exits `0`. The boot check is skipped while it
  runs, so a misconfigured deployment, a broken factor model included, can still run the command to see every
  problem.

## Failure / Edge Cases

- A malformed or out-of-range setting fails the boot, naming the key, before the application serves anything. One
  changed after boot (in a test, or a configuration repository changed at runtime) fails when the manager is next
  resolved, or when the setting is next read.
- `mfa:check` prints each problem as an error with its subject, and exits `1`.
- A binding made in a provider's `boot()` counts, because the boot check waits for every provider. A binding made later
  (in a route, a middleware) does not, and the check refuses the configuration without it.
- A storage connection that is not a name is reported under `storage` and again under `factor`, whose check compares
  the factor model's connection with it.
- An application block that two checks read (its settings, then its delivery bindings) reports a malformed setting
  once.
- The recovery code alphabet is printable ASCII without spaces or hyphens: normalisation would remove them, and a
  multi-byte character could not be drawn one byte at a time. A character repeated, or two that differ only in case,
  are refused, as the draw would favour them.
- A configuration maintenance command, or `artisan -v mfa:check`, boots without the check; any other command boots
  with it.

## Implementation Anchors

- `config/mfa.php`.
- `src/Applications/ApplicationSettings.php`, `src/Applications/ApplicationBlock.php`,
  `src/Applications/DeclaredFirstFactor.php`, `src/Enums/RequirementMode.php`.
- `src/Drivers/TotpSettings.php`, `src/Codes/CodeSettings.php`, `src/RecoveryCodes/RecoveryCodeSettings.php`,
  `src/Attempts/AttemptSettings.php`, `src/Enrollment/EnrollmentSettings.php`, `src/Proofs/ProofSettings.php`,
  `src/Lifecycle/LifecycleSettings.php`, `src/Config/IntegerSetting.php`.
- `src/Config/ConfigurationValidator.php`: `report()`, `validate()`; `src/Config/ConfigurationBindings.php`: `boot()`,
  `validate()`; `src/MfaServiceProvider.php`: `boot()`, `registerManager()`.
- `src/Console/CheckConfigurationCommand.php`; `src/Exceptions/InvalidConfigurationException.php`.
- The readers: `src/Drivers/DriverBindings.php`, `src/RecoveryCodes/RecoveryCodeService.php`,
  `src/Attempts/AttemptService.php` (`attempt()`, `lockout()`), `src/Http/Middleware/RequireMfa.php`
  (`configuredMaxAgeMinutes()`).

## Authoritative Tests

- `tests/Unit/Applications/ApplicationSettingsTest.php`
- `tests/Unit/Applications/DeclaredFirstFactorTest.php`
- `tests/Unit/Drivers/TotpSettingsTest.php`, `tests/Unit/Codes/CodeSettingsTest.php`,
  `tests/Unit/RecoveryCodes/RecoveryCodeSettingsTest.php`, `tests/Unit/Attempts/AttemptSettingsTest.php`,
  `tests/Unit/Enrollment/EnrollmentSettingsTest.php`, `tests/Unit/Proofs/ProofSettingsTest.php`,
  `tests/Unit/Lifecycle/LifecycleSettingsTest.php`
- `tests/Unit/Config/IntegerSettingTest.php`
- `tests/Unit/Config/ConfigurationValidatorTest.php`
- `tests/Unit/Config/ConfigurationBindingsTest.php`
- `tests/Feature/Console/CheckConfigurationCommandTest.php`, `testTheCommandReportsAFactorModelProblemPresentAtBoot`
- `tests/Unit/MfaServiceProviderTest.php` `testBootRefusesAnInvalidConfiguration`,
  `testResolvingTheManagerRefusesAnInvalidConfiguration`

## Change Triggers

- A new setting: it goes in its capability's block or the application block, with a default inside its bounds, a
  reader on that block's settings class, a check in its `validate()`, and a row in the configuration guide.
- A new capability block: a settings class of its own, and a subject in `ConfigurationValidator`.
- A new binding rule (a seam an enabled feature needs): a check in `ConfigurationValidator` under the application's
  subject.
- Any change to a bound the specifications set, or to the entropy measure of recovery codes.
