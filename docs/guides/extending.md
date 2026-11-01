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
| Enforcement policy         | Implement `Contracts\MfaPolicy` and bind it in the container                           |
| Verification store         | Implement `Contracts\MfaVerificationStore` and bind it in the container                |
| SMS delivery               | Implement `Contracts\SmsGateway` and bind it in the container                          |
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

## Factor drivers

A driver is one factor type behind `Contracts\FactorDriver`, registered under the type's name:

| Method                            | Answers                                                                                        |
|-----------------------------------|------------------------------------------------------------------------------------------------|
| `channelKind()`                   | The `Enums\ChannelKind` the type's factors travel on, which the combination policy reads       |
| `amr()`                           | The RFC 8176 `amr` values a proof by the type adds on its own, such as `otp` or `sms`          |
| `startEnrollment(Factor $factor)` | The secret to store on the pending factor and show the person once, or `null` when it has none |
| `confirm(Factor $factor, $code)`  | Whether the first code the person submits confirms the pending factor                          |
| `issueChallenge(Factor $factor)`  | Send a code where the type delivers one; nothing where codes are made where they are held      |
| `verify(Factor $factor, $code)`   | Whether the code proves the factor, compared in constant time                                  |

The type fixes the channel kind, so the combination policy never infers a channel from a type's name. A driver claims
only the `amr` values its method always adds: values that depend on what a proof observed, such as user presence, are
not the driver's to claim. The shipped drivers state:

| Type    | Channel kind        | `amr` |
|---------|---------------------|-------|
| `totp`  | `authenticator_app` | `otp` |
| `sms`   | `sms`               | `sms` |
| `email` | `email`             | `otp` |

A driver leaves attempt counters, lockouts, events and the verification record to the services around it, and may
change only the single-use material its type keeps when it is spent.

Bind your implementations in a service provider's `register()` or `boot()`: the package checks its configuration once
every provider has booted (see [Checking the configuration](configuration.md#checking-the-configuration)), and refuses an
application that enables `sms` while the default `NullSmsGateway` is still bound, or that neither declares its first
factor nor has a `Contracts\FirstFactorResolver` bound.

In tests, bind `Testing\FakeSmsGateway` as the `SmsGateway` to capture the messages the SMS driver sends instead of
delivering them.

## Where the classes live

The package is organised by capability. Each capability's namespace holds its service, the `*Bindings` class that
registers it with the container, and the classes only it uses:

| Namespace       | Holds                                                                                               |
|-----------------|-----------------------------------------------------------------------------------------------------|
| `Factors`       | Factor reads, their cache, ownership, `FactorSummary` and `OperationGuard`                          |
| `Drivers`       | The TOTP, email and SMS drivers, the resolver the services run drivers through, `TotpSettings`      |
| `Codes`         | Delivery of email and SMS codes: `MfaCodeMessage`, the default `NullSmsGateway`, `CodeSettings`     |
| `Requirements`  | Whether MFA applies (`shouldUse()`), the default `NullMfaPolicy`, `Requirement`                     |
| `Proofs`        | The recorded verification (`hasExpired()`), `SessionMfaVerificationStore`, `Proof`, `ProofSettings` |
| `Verification`  | `challenge()`, `verify()` and `VerificationResult`                                                  |
| `Assurance`     | `Channel`, `ObservedProperties`, `Evaluation` and the default `DefaultCombinationPolicy`            |
| `Context`       | `PendingContext` and the default event context resolver                                             |
| `Passkeys`      | `PasskeyAssertion`, what a verified passkey assertion observed                                      |
| `Enrollment`    | `enroll()` and `EnrollmentSettings`                                                                 |
| `Lifecycle`     | `disable()`, `ForgetIdentity` and `LifecycleSettings`                                               |
| `RecoveryCodes` | Backup codes: `issueBackupCodes()`, `BackupCodeDriver` and `RecoveryCodeSettings`                   |
| `Attempts`      | `AttemptSettings`, the attempt caps and lockouts                                                    |
| `Applications`  | `ApplicationSettings`, what each application accepts and offers, and `DeclaredFirstFactor`          |
| `Http`          | The `mfa` and `mfa.skip` middleware, `RequireMfa` and `SkipMfa`                                     |
| `Testing`       | Test doubles for applications: `FakeSmsGateway`                                                     |
| `Console`       | The `mfa:check` command                                                                             |

`Contracts`, `Concerns`, `Models`, `Events`, `Exceptions`, `Enums` and `Facades` hold what their names say for every
capability (the events and how they are dispatched are in [Events](events.md), and the values and enums assurance is
described with in [Proofs, assurance and requirements](assurance.md)),
and `Config`, `Database` and `Support` the internal helpers the capabilities share, among them
`Config\ConfigurationValidator` (see [Checking the configuration](configuration.md#checking-the-configuration)),
`Database\StorageConnection` and `Support\FactorStateTransaction` (see [Storage](configuration.md#storage)). Each
capability reads its own block of `config/mfa.php` through its `*Settings` class, on every call.
`Contracts` also declares the seams the requirement, verification, enrolment and lifecycle flows are built against,
listed in [the seam contracts design note](../design/seam-contracts.md). No shipped flow calls them yet, and binding
one changes nothing until its flow does. Only `CombinationPolicy` is bound by default, to
`Assurance\DefaultCombinationPolicy` (see [Combination policy](assurance.md#combination-policy)), ahead of the flows
that will use it; the others are not bound until their flows are in place. The `Mfa`
facade and `MfaManager` stay the entry point: each manager method hands its call to the service of its capability, so
nothing you call changes with the layout. The services and `*Bindings` classes are internal; extend the package through
the points in the table above. How the layout works is described in
[the capability services design note](../design/capability-services.md).
