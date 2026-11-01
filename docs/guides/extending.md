# Extending

## Extensibility

Concrete classes in this package are `final` except `MfaManager`, the shipped `Models\Factor` model and the
`Codes\MfaCodeMessage` mailable. Extension is through **composition and DI**, not inheritance:

| Extension point            | How                                                                                    |
|----------------------------|----------------------------------------------------------------------------------------|
| Custom factor driver       | Implement `Contracts\FactorDriver`, register it with `Mfa::extend()`                   |
| Replacing a shipped driver | Register yours under the same name with `Mfa::extend()`                                |
| Custom identity model      | Implement `Contracts\MultiFactorAuthenticatable` on your identity                      |
| Enforcement policy         | Implement `Contracts\MfaPolicy` and bind it in the container                           |
| Verification store         | Implement `Contracts\MfaVerificationStore` and bind it in the container                |
| SMS delivery               | Implement `Contracts\SmsGateway` and bind it in the container                          |
| Email code message         | Extend `Codes\MfaCodeMessage` and set `mfa.drivers.email.mailable`                     |
| Custom factor model        | Extend `Models\Factor` or implement `Contracts\EloquentFactor`; set `mfa.factor.model` |

Every class name above is relative to `SineMacula\Laravel\Mfa`. Bind your own implementations from a service provider: a
binding made after the package's provider has registered replaces the package's default, and `Mfa::extend()` replaces a
shipped driver of the same name. So does a driver registered on the manager from a container extender or a resolving
callback on `mfa`, since the shipped drivers are registered before either runs. Register drivers before any code calls
`Mfa::driver(...)`, since the manager keeps a driver once it is built.

A custom factor model lives on the storage connection with the package's other tables (see
[Storage](configuration.md#storage)): one on another connection is refused when the package boots.

In tests, bind `Testing\FakeSmsGateway` as the `SmsGateway` to capture the messages the SMS driver sends instead of
delivering them.

## Where the classes live

The package is organised by capability. Each capability's namespace holds its service, the `*Bindings` class that
registers it with the container, and the classes only it uses:

| Namespace       | Holds                                                                               |
|-----------------|-------------------------------------------------------------------------------------|
| `Factors`       | Factor reads (`isSetup()`, `getFactors()`), their cache, ownership, `FactorSummary` |
| `Drivers`       | The TOTP, email and SMS drivers, and the resolver the services run drivers through  |
| `Codes`         | Delivery of email and SMS codes: `MfaCodeMessage` and the default `NullSmsGateway`  |
| `Requirements`  | Whether MFA applies (`shouldUse()`), the default `NullMfaPolicy`, `Requirement`     |
| `Proofs`        | The recorded verification (`hasExpired()`), `SessionMfaVerificationStore`, `Proof`  |
| `Verification`  | `challenge()`, `verify()` and `VerificationResult`                                  |
| `Assurance`     | `Channel`, `ObservedProperties` and `Evaluation`                                    |
| `Context`       | `PendingContext`, a pending session as an authentication layer resolves it          |
| `Passkeys`      | `PasskeyAssertion`, what a verified passkey assertion observed                      |
| `Enrollment`    | `enroll()`                                                                          |
| `Lifecycle`     | `disable()`                                                                         |
| `RecoveryCodes` | Backup codes: `issueBackupCodes()` and `BackupCodeDriver`                           |
| `Http`          | The `mfa` and `mfa.skip` middleware, `RequireMfa` and `SkipMfa`                     |
| `Testing`       | Test doubles for applications: `FakeSmsGateway`                                     |

`Contracts`, `Concerns`, `Models`, `Events`, `Exceptions`, `Enums` and `Facades` hold what their names say for every
capability (the values and enums assurance is described with are in [Proofs, assurance and requirements](assurance.md)),
and `Config`, `Database` and `Support` the internal helpers the capabilities share, among them
`Database\StorageConnection` and `Support\FactorStateTransaction` (see [Storage](configuration.md#storage)).
`Contracts` also declares the seams the requirement, verification, enrolment and lifecycle flows are built against,
listed in [the seam contracts design note](../design/seam-contracts.md); no shipped flow calls them yet, so none is
bound by default, and binding one changes nothing until its flow does. The `Mfa` facade and `MfaManager`
stay the entry point: each manager method hands its call to the service of its capability, so nothing you call changes
with the layout. The services and `*Bindings` classes are internal; extend the package through the points in the table
above. How the layout works is described in [the capability services design note](../design/capability-services.md).
