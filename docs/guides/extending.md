# Extending

## Extensibility

Concrete classes in this package are `final` except `MfaManager`, the shipped `Models\Factor` and `Models\RecoveryCode`
models and the `Codes\MfaCodeMessage` mailable. Extension is through **composition and DI**, not inheritance:

| Extension point            | How                                                                                    |
|----------------------------|----------------------------------------------------------------------------------------|
| Custom factor driver       | Implement `Contracts\FactorDriver`, register it with `Mfa::extend()`                   |
| Replacing a shipped driver | Register yours under the same name with `Mfa::extend()`                                |
| Custom identity model      | Implement `Contracts\MultiFactorAuthenticatable` and use `Concerns\HasFactors`         |
| Event context              | Implement `Contracts\EventContextResolver` and bind it in the container                |
| Requirements and freshness | Implement `Contracts\RequirementPolicy`, `FreshnessGate` and the others; bind them     |
| Proof store                | Implement `Contracts\ProofStore` and bind it in the container                          |
| Authentication seams       | Implement the seams in [Seam defaults](#seam-defaults) and bind them                   |
| Passkeys                   | Implement `Contracts\PasskeyGateway` and bind it; call `Passkeys\PasskeyChangeGate`    |
| SMS delivery               | Implement `Contracts\SmsSender` and bind it in the container                           |
| Email delivery             | Implement `Contracts\EmailSender`, or use `Codes\MailEmailSender`, and bind it         |
| Email code message         | Extend `Codes\MfaCodeMessage` and set `mfa.codes.mailable`                             |
| Custom factor model        | Extend `Models\Factor` or implement `Contracts\EloquentFactor`; set `mfa.factor.model` |
| Custom recovery code model | Extend `Models\RecoveryCode` or implement `Contracts\RecoveryCode`; set the model      |

Every class name above is relative to `SineMacula\Laravel\Mfa`. Bind your own implementations from a service provider: a
binding made after the package's provider has registered replaces the package's default, and `Mfa::extend()` replaces a
shipped driver of the same name. So does a driver registered on the manager from a container extender or a resolving
callback on `mfa`, since the shipped drivers are registered before either runs. Register drivers before any code calls
`Mfa::driver(...)`, since the manager keeps a driver once it is built.

A custom factor or recovery code model lives on the storage connection with the package's other tables (see
[Storage](configuration.md#storage)): one on another connection is refused when the package boots. The recovery code
model is set with `mfa.recovery_codes.model`. Identity models are described in [Identity models](identity-models.md).

A custom factor model that implements `Contracts\EloquentFactor` itself, rather than through `Concerns\ActsAsFactor`,
must make `storeAcceptedStep()` a compare-and-set on its stored row: record the TOTP time step only when it is later
than the stored one, in one atomic statement, and report whether it did. The TOTP driver accepts a code only when the
step is recorded, so each time step is used once per factor however many requests race with it (see
[the TOTP design note](../design/totp.md)). A factor implementing only `Contracts\Factor` has nowhere to record a step,
so the TOTP driver accepts no code for it.

`TotpDriver::startEnrollment()` stamps the TOTP parameters on an Eloquent factor itself. A factor of another kind is
given them by its caller: `TotpDriver::parameters()` returns a `Drivers\TotpParameters` whose public `algorithm`
(`sha1`, `sha256` or `sha512`), `digits` (6 to 8) and `period` (15 to 120 seconds) are what the factor's
`getTotpAlgorithm()`, `getTotpDigits()` and `getTotpPeriod()` must return from then on, whatever the configuration
later says.

## Factor drivers

A driver is one factor type behind `Contracts\FactorDriver`, registered under the type's name:

| Method                            | Answers                                                                                        |
|-----------------------------------|------------------------------------------------------------------------------------------------|
| `channelKind()`                   | The `Enums\ChannelKind` the type's factors travel on, which the combination policy reads       |
| `amr()`                           | The RFC 8176 `amr` values a proof by the type adds on its own, such as `otp` or `sms`          |
| `startEnrollment(Factor $factor)` | The secret to store on the pending factor and show the person once, or `null` when it has none |
| `confirm(Factor $factor, $code)`  | Whether the first code the person submits confirms the pending factor                          |
| `issueChallenge(Factor $factor)`  | Issue a challenge: nothing for TOTP; delivered codes go through `deliver()` instead            |
| `verify(Factor $factor, $code)`   | Whether the code proves the factor, compared in constant time                                  |

The type fixes the channel kind, so the combination policy never infers a channel from a type's name. A driver claims
only the `amr` values its method always adds: values that depend on what a proof observed, such as user presence, are
not the driver's to claim. The shipped drivers state:

| Type      | Channel kind        | `amr`  |
|-----------|---------------------|--------|
| `totp`    | `authenticator_app` | `otp`  |
| `sms`     | `sms`               | `sms`  |
| `email`   | `email`             | `otp`  |
| `passkey` | `passkey`           | (none) |

The `passkey` driver only states its channel: a passkey is never confirmed or proved by a code, and its `amr` values
come from what each assertion observed (see [Passkeys](#passkeys)).

A driver leaves attempt counters, lockouts, events and the verification record to the services around it, and may
change only the single-use material its type keeps when it is spent.

A type whose codes are delivered to a destination implements `Contracts\CodeDeliveryDriver` as well, usually by
extending `Drivers\AbstractCodeDriver`, as the email and SMS drivers do. The package then draws, stores and checks its
codes itself, bound to the factor, the session, the application and the purpose (see
[Delivered codes](configuration.md#delivered-codes)), and the driver only delivers each one with `deliver()`: it never
sees or keeps a code otherwise, and its `issueChallenge()`, `verify()` and `confirm()` refuse to work on a factor
alone.

Bind your implementations in a service provider's `register()` or `boot()`: the package checks its configuration once
every provider has booted (see [Checking the configuration](configuration.md#checking-the-configuration)), and refuses an
application that enables `sms` or `email` while the default `NullSmsSender` or `NullEmailSender` is still bound, or
that neither declares its first factor nor has a `Contracts\FirstFactorResolver` bound. To send email codes through
Laravel's mailer, bind the package's own sender:

```php
use SineMacula\Laravel\Mfa\Codes\MailEmailSender;
use SineMacula\Laravel\Mfa\Contracts\EmailSender;

$this->app->singleton(EmailSender::class, MailEmailSender::class);
```

An `SmsSender` is handed the message with the code in clear. One that queues it must encrypt the queued payload, for
example with a job that implements `ShouldBeEncrypted`, and none may log it. The package's `MfaCodeMessage` encrypts its
own queued payload, so an `EmailSender` that queues it needs nothing more.

In tests, `Testing\FakeSmsSender::fake()` and `Testing\FakeEmailSender::fake()` bind a sender that keeps the messages
the drivers send instead of delivering them, and returns it, so a test can read the code it was sent
(`lastMessageTo()`, `lastCodeTo()`). Faking also makes the manager build its drivers again, so a driver resolved before
the fake sends through it too.

## Where the classes live

The package is organised by capability. Each capability's namespace holds its service, the `*Bindings` class that
registers it with the container, and the classes only it uses:

| Namespace       | Holds                                                                                               |
|-----------------|-----------------------------------------------------------------------------------------------------|
| `Factors`       | Factor reads, ownership, `FactorSummary` and `OperationGuard`                                       |
| `Drivers`       | The TOTP, email, SMS and passkey drivers, the resolver the services run drivers through             |
| `Codes`         | Delivered codes: `CodeService`, the senders' defaults, `PackageChallengeGateway`, `MfaCodeMessage`  |
| `Requirements`  | `requirement()`, `isFresh()`, `Requirement` and the requirement seams' defaults                     |
| `Proofs`        | The sign-in's proofs (`proofs()`), `SessionProofStore`, `GuardHooks`, `Proof`, `ProofSettings`      |
| `Verification`  | `challenge()`, `verify()` and `VerificationResult`                                                  |
| `Assurance`     | `Channel`, `ObservedProperties`, `Evaluation` and the default `DefaultCombinationPolicy`            |
| `Context`       | `PendingContext`, who a request serves, and the pending session and subject type defaults           |
| `Passkeys`      | The change gate, `PasskeyRegistration`, `CredentialId`, assertions and the unavailable gateway      |
| `Seams`         | Defaults that read nothing of the package: `RefusingReauthenticator`                                |
| `Enrollment`    | `enroll()` and `EnrollmentSettings`                                                                 |
| `Lifecycle`     | `disable()`, `ForgetIdentity` and `LifecycleSettings`                                               |
| `RecoveryCodes` | `generateRecoveryCodes()`, `redeemRecoveryCode()`, `recoveryCodes()` and `RecoveryCodeSettings`     |
| `Attempts`      | `AttemptService`, and `ChallengeCounters`, the counts a challenge owner reports into                |
| `Applications`  | `ApplicationSettings`, what each application accepts and offers, and `DeclaredFirstFactor`          |
| `Secrets`       | `RevealedSecret`, `SecretResponse`, the `mfa.no-store` middleware and the log redaction             |
| `Http`          | The `mfa` and `mfa.skip` middleware, `RequireMfa` and `SkipMfa`                                     |
| `Testing`       | `FakeSmsSender`, `FakeEmailSender`, and the seam contract kit in `Testing\Seams`                    |
| `Console`       | The `mfa:check` command                                                                             |

`Contracts`, `Concerns`, `Models`, `Events`, `Exceptions`, `Enums` and `Facades` hold what their names say for every
capability (the events and how they are dispatched are in [Events](events.md), and the values and enums assurance is
described with in [Proofs, assurance and requirements](assurance.md)),
and `Config`, `Database` and `Support` the internal helpers the capabilities share, among them
`Config\ConfigurationValidator` (see [Checking the configuration](configuration.md#checking-the-configuration)),
`Database\StorageConnection` and `Support\FactorStateTransaction` (see [Storage](configuration.md#storage)). Each
capability reads its own block of `config/mfa.php` through its `*Settings` class, on every call.
`Contracts` also declares the seams the requirement, verification, enrolment and lifecycle flows are built against,
listed in [the seam contracts design note](../design/seam-contracts.md). Each has a default that works without an
authentication layer and fails closed (see [Seam defaults](#seam-defaults)), but for `PendingCompletion` and `StepUp`,
which come with verification, and `SelfServiceRecovery`, which comes with the lifecycle flows. The `Mfa` facade and
`MfaManager` stay the entry point: each manager method hands its call to the service of its capability, so nothing you
call changes with the layout. The services and `*Bindings` classes are internal; extend the package through the points
in the table above. How the layout works is described in
[the capability services design note](../design/capability-services.md).

## Seam defaults

Every seam is bound to a default that works without an authentication layer and answers the refusing way when it
cannot answer safely. An adapter over an authentication layer, or the application, rebinds any of them in its own
service provider:

| Contract                 | Default                                     | Without an authentication layer                                         |
|--------------------------|---------------------------------------------|-------------------------------------------------------------------------|
| `PendingSessionResolver` | `Context\NoPendingSessionResolver`          | No request carries a pending session                                    |
| `SubjectTypeResolver`    | `Context\IdentityContractSubjectType`       | A person is an identity whose `canHoldFactors()` is true                |
| `FirstFactorResolver`    | `Applications\DeclaredFirstFactorResolver`  | The application's `first_factor`, dated at the Unix epoch               |
| `Reauthenticator`        | `Seams\RefusingReauthenticator`             | Nothing proves the first factor again                                   |
| `SessionRevoker`         | `Proofs\GenerationSessionRevoker`           | The verification generation advances; other sessions verify again       |
| `SessionTransition`      | `Http\MiddlewareSessionTransition`          | Nothing to change: the `mfa` middleware gates the session               |
| `ChallengeGateway`       | `Codes\PackageChallengeGateway`             | The package's own delivered codes                                       |
| `PasskeyGateway`         | `Passkeys\UnavailablePasskeyGateway`        | Passkeys are unavailable                                                |
| `LastFactorPolicy`       | `Lifecycle\RequiredFactorPolicy`            | The last acceptable factor stays while one is required                  |

The refusing reauthenticator means an identity cannot add its first additional factor on an active session until
something proves its first factor again: bind a `Contracts\Reauthenticator` that asks the person for their password, for
example, and returns a `first_factor_reauthentication` proof bound to their current sign-in.

Every helper that returns summaries, sends a code or reveals a secret asks the bound `PendingSessionResolver` first.
On a pending session it serves only the action it needs (`mfa.list_factors` for `getFactors()` and `recoveryCodes()`,
`mfa.send_code` for `challenge()`, `mfa.verify` for `verify()`, `redeemRecoveryCode()` and passkey assertions), as the
pending session's own identity; anything else gets nothing, never the guard's user in its place. Generating recovery
codes, enrolling a factor directly, `disable()`, `isSetup()` and `proofs()` serve active sessions only. A code is sent
or checked only for a binding that is exactly the caller's own, on its application and its session. A resolver reports
a pending credential that does not validate by throwing.

## Challenge counters

Whoever owns a delivered factor's challenges (the package's own `Codes\PackageChallengeGateway`, or an authentication
layer's adapter behind `Contracts\ChallengeGateway`) reports to `Attempts\ChallengeCounters`, inside the transaction on
the storage connection that consumes the challenge:

```php
DB::transaction(function () use ($counters, $identity, $factor, $binding, $code): bool {
    if (!$counters->isUsable($identity, $factor, $binding)->isAdmitted()) {
        return false;
    }

    $passed = $this->consume($binding, $code); // the owner's own challenge, locked and consumed here

    return $counters->report($identity, $factor, $binding, $passed)->passed;
});
```

Both calls refuse with a `LogicException` outside a transaction. `isUsable()` takes the identity's factor state lock,
which is held until the owner commits, so parallel guesses are counted one after the other; ask it before sending a code
too, and never report a delivery. The lock order is the identity's state, then its factors, then the owner's challenge.

`Testing\Seams\Concerns\ChallengeCountersTests` proves an owner's wiring: a failure is counted before the owner's
transaction commits and not at all when it, or a nested transaction around the challenge, rolls back; the identity's
limit locks it; a consumed challenge answered again never counts as a success; and a disabled factor is not challenged.
Its hooks fail one challenge, and consume one and answer it again, through the owner's own path.

## Passkeys

A passkey is a factor only through an association record this package keeps; the credential and its ceremonies stay
with the authentication layer, reached through a `Contracts\PasskeyGateway` the application binds. Credential ids are
their canonical unpadded base64url form (`Passkeys\CredentialId`), compared exactly; any other encoding is refused.

Every path that registers, removes or changes a passkey calls `Passkeys\PasskeyChangeGate` first, inside its own
transaction on the storage connection:

```php
DB::transaction(function () use ($gate, $identity, $application, $credential, $properties, $binding): void {
    $this->storeCredential($credential); // the authentication layer's own write

    $result = $gate->registering($identity, $application, new PasskeyRegistration($credential, $properties, $binding));

    // Reveal $result?->recoveryCodes only once this transaction has committed.
});
```

`registering()` associates the passkey as a confirmed factor when the application enables `passkey`, after the same
checks an enrolment needs: a fresh step-up for a further factor, the first factor proved again for the first one, or the
bootstrap path on a pending session that allows `mfa.confirm_bootstrap_enrollment`; then the application's limits. It
returns `null` when the application does not enable the type, and recovery codes with the identity's first additional
factor. `removing()` removes the factor with a fresh step-up made with another factor where the identity has one,
under the last factor policy, and stops the identity's other sessions counting. `changing()` refuses any change to an
associated credential: register the new one and remove the old. A refusal throws an `OperationRefusedException`; let it
roll back your own change, since catching it and committing breaks the gate.

## Proving an adapter

`Testing\Seams` holds a contract kit for each seam: a trait of tests with abstract hooks, in `Testing\Seams\Concerns`,
which an adapter's test case uses to prove its implementation meets what every implementation must guarantee. The kits
for the challenge counters and the change gate prove the wiring of the calls an authentication layer makes into this
package:

```php
use SineMacula\Laravel\Mfa\Testing\Seams\Concerns\ProofStoreTests;

final class SessionProofStoreAdapterTest extends TestCase
{
    use ProofStoreTests;

    protected function proofStore(): ProofStore
    {
        return $this->app->make(ProofStore::class);
    }

    protected function proofStoreIdentity(): MultiFactorAuthenticatable
    {
        return User::factory()->create();
    }

    protected function proofStoreApplication(): string
    {
        return 'web';
    }
}
```

The kits check safety guarantees, not capabilities a default lacks: a refusing reauthenticator passes, and a revoker
passes when other sessions stop counting whether or not it ends them. Each check is a static assertion on a
`*Contract` class beside its trait, so a test can also call one directly. The kits need PHPUnit and a database migrated
with the package's tables, as any test of an adapter does.

