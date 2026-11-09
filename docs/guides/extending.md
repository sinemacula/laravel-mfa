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
| Email code message         | Extend `Codes\MfaCodeMessage` and set `mfa.codes.mailable`, read by `MailEmailSender`  |
| Custom factor model        | Extend `Models\Factor` or implement `Contracts\EloquentFactor`; set `mfa.factor.model` |
| Custom recovery code model | Extend `Models\RecoveryCode` or implement `Contracts\RecoveryCode`; set the model      |

Every class name above is relative to `SineMacula\Laravel\Mfa`. Bind your own implementations from a service provider. The
package binds each default only when nothing is bound yet, so a binding made before its provider registers is kept, as
one made after replaces the default, whichever order Composer registers the providers in. `Mfa::extend()` replaces a
shipped driver of the same name. So does a driver registered on the manager from a container extender or a resolving
callback on `mfa`, since the shipped drivers are registered before either runs. The manager builds a driver on every
call rather than caching it, so the most recent registration is the one used, but call `extend()` from a service
provider: a closure registered from inside a request stays on the shared manager.

A driver keeps no state between calls, as it is built for each one, a few small objects for the shipped ones, and two
resolutions are two objects. A driver that is expensive to build is registered as
`Mfa::extend('mine', fn ($app) => $app->make(MyDriver::class))` and bound as it likes. A creator is handed the
application current at the time, not the one it was registered on, so it reads its configuration and sender from there.

A custom factor or recovery code model lives on the storage connection with the package's other tables (see
[Storage](configuration.md#storage)): one on another connection is refused when the package boots. The recovery code
model is set with `mfa.recovery_codes.model`. Identity models are described in [Identity models](identity-models.md).

A custom factor model keeps its temporary lockout on its own row, in the column `getLockedUntilName()` names
(`locked_until` by default), and when the failure ceiling disabled it in the column `getDisabledAtName()` names
(`disabled_at` by default). `Concerns\ActsAsFactor` casts both columns as a `datetime` itself, whatever they are named,
so the model need declare no cast for them, and any cast it does declare is left as it is. A stored value in either that
does not read as a time throws rather than reads as unlocked or enabled. So does a status, in the column
`getStatusName()` names, that is neither `pending` nor `confirmed` (or the `FactorStatus` case for either): it is never
read as pending, as a factor read as not confirmed can let a weaker proof through, and only a new factor not yet given a
status reads as pending. A model that casts the status to `Enums\FactorStatus` throws Laravel's `ValueError` from the
cast instead of `InvalidModelException` for a value the enum does not know, which fails closed the same way. A reset
removes such a factor (see [Factor lifecycle](lifecycle.md)). A model implementing `Contracts\EloquentFactor` without
the trait must do the same. A factor implementing only `Contracts\Factor` has no row, and so no lockout of its own.

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

| Method                                     | Answers                                                                                      |
|--------------------------------------------|----------------------------------------------------------------------------------------------|
| `channelKind()`                            | The `Enums\ChannelKind` the type's factors travel on, which the combination policy reads     |
| `amr()`                                    | The RFC 8176 `amr` values a proof by the type adds on its own, such as `otp` or `sms`        |
| `startEnrollment(Factor $factor)`          | The secret, as a `RevealedSecret`, to store on the pending factor and show once, or `null`   |
| `confirm(Factor $factor, $code, $binding)` | The `CodeCheck` of the first code the person submits, as `verify()` answers                  |
| `verify(Factor $factor, $code, $binding)`  | `CodeCheck::ACCEPTED`, `INVALID`, or `REPLAYED` for a code that matches but was already used |

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

A driver leaves attempt counters, lockouts, events and the verification record to the services around it, and may change
only the single-use material its type keeps when it is spent; that write stays in the transaction a later refusal rolls
back. It compares in constant time, is handed the factor as stored under the identity's lock, and reads the binding for
what depends on the application, as the TOTP window does.

A type whose codes are delivered to a destination implements `Contracts\CodeDeliveryDriver` as well, usually by
extending `Drivers\AbstractCodeDriver`, as the email and SMS drivers do. The bound `ChallengeGateway` then draws, stores
and checks its codes, bound to the factor, the session, the application and the purpose (see
[Delivered codes](configuration.md#delivered-codes)), and the driver only delivers each one with `deliver()`, given the
factor as locked and a `Codes\CodeMessage` to send to the message's destination: it never sees or keeps a code
otherwise, and its `verify()` and `confirm()` refuse to work on a factor alone.

Bind your implementations in a service provider's `register()` or `boot()`: the package checks its configuration once
every provider has booted (see [Checking the configuration](configuration.md#checking-the-configuration)), and refuses
an application that enables `sms` or `email` while the default `NullSmsSender` or `NullEmailSender` is still bound, or
that neither declares its first factor nor has a `Contracts\FirstFactorResolver` bound. To send email codes through
Laravel's mailer, bind the package's own sender:

```php
use SineMacula\Laravel\Mfa\Codes\MailEmailSender;
use SineMacula\Laravel\Mfa\Contracts\EmailSender;

$this->app->bind(EmailSender::class, MailEmailSender::class);
```

Bind a sender with `bind()`, as above, unless it is one with no request state: under Octane or in a queue worker a
`singleton()` is kept for the life of the process (see [Operations](operations.md#octane)).

A sender is given a `Codes\CodeMessage`, the neutral details of one code, and writes the message itself:

| Field           | What it holds                                                                   |
|-----------------|---------------------------------------------------------------------------------|
| `application`   | The application the code is for                                                 |
| `purpose`       | `Enums\Purpose`: `sign_in`, `reauthenticate`, `step_up` or `enrollment`         |
| `type`          | The factor's type, such as `sms` or `email`                                     |
| `destination()` | The factor's phone number or address, in the form it keeps                      |
| `code`          | A `Secrets\RevealedSecret`: call `reveal()` only to put the code in the message |
| `expiresAt`     | When the code stops working                                                     |
| `recipient()`   | The identity the code is for                                                    |
| `factor`        | The factor's `Factors\FactorSummary`, its destination masked                    |

The destination and the recipient are read through methods, and the code is a `RevealedSecret`, so no dump of the
message shows them. The summary's label is the person's own text and is shown as it is. A sender is called while the
code is drawn, inside the identity's transaction: a throw is the delivery's failure, and the code is then not kept.
One that queues the message must encrypt the whole queued payload, destination included, for example with a job that
implements `ShouldBeEncrypted`, and none may log the code. A queued job that fails later cannot take back a code already
reported sent.

`Codes\MailEmailSender` lays the code out in the configured `mfa.codes.mailable` (`Codes\MfaCodeMessage` or a
subclass), in the locale it is sent in, and encrypts it whenever it is queued. For SMS, `Codes\SmsCodeText::of()` gives
the package's own wording, the `mfa::messages.sms_code` line in the current locale (see
[Localisation](localization.md)), for a sender that keeps it. In tests, `Testing\FakeSmsSender::fake()` and
`Testing\FakeEmailSender::fake()` bind a sender that keeps the messages instead of delivering them (see
[Testing](testing.md)).

A driver whose secret an authenticator app reads from a QR code also implements `Contracts\ProvisioningDriver`:
`provisioningUri(Factor $factor, $issuer, $accountName, RevealedSecret $secret)` returns the URI as a `RevealedSecret`,
and a start then needs an account name, which `EnrollmentRequest::provisioned($type, $accountName)` supplies. A driver
delivering codes implements `Contracts\CodeDeliveryDriver`: `normalizeDestination($destination)` returns the one form
the factor keeps, and independence is compared in, or `null` for a destination it cannot deliver to
(`invalid_destination`).

An adapter's `FreshnessGate` answers `freshUntil()` as well as `isFresh()`: the instant the session stops being fresh
for the operation on the proofs it holds now, or `null` when it is not fresh or it cannot say, which refuses the
enrolment it would have authorised. Where the gate cannot express a minimum level or independently aged parts in its own
terms, it evaluates the package's requirement too and answers the earlier of the two deadlines.
`PendingContext::$expiresAt` is the pending session's own expiry, which a bootstrap enrolment grant lives no longer
than. Under a binding whose purpose is `enrollment`, a `ChallengeGateway` is handed a pending factor;
`Attempts\ChallengeCounters` admits it and `report()` is silent, so the enrolment's own cap is what counts. A restart
makes a new factor, so a gateway whose send caps or cooldown are keyed on the factor must carry them across, by keying
them on what a restart keeps, such as the owner and the destination.

## Where the classes live

The package is organised by capability. Each capability's namespace holds its service, the `*Bindings` class that
registers it with the container, and the classes only it uses:

| Namespace       | Holds                                                                                                             |
|-----------------|-------------------------------------------------------------------------------------------------------------------|
| `Factors`       | Factor reads, `FactorSummary` and `OperationGuard`                                                                |
| `Drivers`       | The TOTP, email, SMS and passkey drivers, the resolver the services run drivers through                           |
| `Codes`         | Delivered codes: `CodeService`, `CodeMessage`, the senders' defaults, `PackageChallengeGateway`, `MfaCodeMessage` |
| `Requirements`  | `requirement()`, `isFresh()`, `stepUpRefusal()`, `Requirement` and the requirement seams' defaults                |
| `Proofs`        | The sign-in's proofs, `SessionProofStore`, `ProofStoreCompletion`, `GuardHooks`, `Proof`                          |
| `Verification`  | `verify()`, `sendCode()`, `offeredFactors()`, `Submission` and `VerificationResult`                               |
| `Assurance`     | `Channel`, `ObservedProperties`, `Evaluation` and the default `DefaultCombinationPolicy`                          |
| `Context`       | `CallerContext`, `ClientContext`, `PendingContext`, the defaults, and `AuthenticationContextContributor`          |
| `Passkeys`      | The change gate, `PasskeyRegistration`, `CredentialId`, assertions and the unavailable gateway                    |
| `Seams`         | Defaults that read nothing of the package: `RefusingReauthenticator`                                              |
| `Enrollment`    | `startEnrollment()`, `confirmEnrollment()`, what they answer and `EnrollmentSettings`                             |
| `Lifecycle`     | Removing, resetting, unlocking, forgetting and pruning, and `LifecycleSettings`                                   |
| `RecoveryCodes` | `generateRecoveryCodes()`, `recoveryCodeStatus()` and `RecoveryCodeSettings`                                      |
| `Attempts`      | `AttemptService`, and `ChallengeCounters`, the counts a challenge owner reports into                              |
| `Applications`  | `ApplicationSettings`, what each application accepts and offers, and `DeclaredFirstFactor`                        |
| `Secrets`       | `RevealedSecret`, `SecretResponse`, the `mfa.no-store` middleware and the log redaction                           |
| `Http`          | The `mfa` and `mfa.exempt` middleware, `EnsureMfaRequirementIsMet` and `ExemptFromMfa`                            |
| `Testing`       | The fakes, `AuthenticatorApp`, `Concerns\InteractsWithMfa`, and the kit in `Testing\Seams`                        |
| `Console`       | The `mfa:check` and `mfa:prune` commands                                                                          |

`Contracts`, `Concerns`, `Models`, `Events`, `Exceptions`, `Enums` and `Facades` hold what their names say for every
capability (the events and how they are dispatched are in [Events](events.md), and the values and enums assurance is
described with in [Proofs, assurance and requirements](assurance.md)),
and `Config`, `Database` and `Support` the internal helpers the capabilities share, among them
`Config\ConfigurationValidator` (see [Checking the configuration](configuration.md#checking-the-configuration)),
`Database\StorageConnection` and `Support\FactorStateTransaction` (see [Storage](configuration.md#storage)). Each
capability reads its own block of `config/mfa.php` through its `*Settings` class, on every call.
`Contracts` also declares the seams the requirement, verification, enrolment and lifecycle flows are built against,
listed in [the seam contracts design note](../design/seam-contracts.md), and those an authentication layer meets in
[Seams with an authentication layer](#seams-with-an-authentication-layer). Each has a default that works without an
authentication layer and fails closed (see [Seam defaults](#seam-defaults)). The `Mfa` facade and
`MfaManager` stay the entry point: each manager method hands its call to the service of its capability, so nothing you
call changes with the layout. The services and `*Bindings` classes are internal; extend the package through the points
in the table above. How the layout works is described in
[the capability services design note](../design/capability-services.md).

## Seam defaults

Every seam is bound to a default that works without an authentication layer and answers the refusing way when it
cannot answer safely. An adapter over an authentication layer, or the application, rebinds any of them in its own
service provider:

| Contract                 | Default                                    | Without an authentication layer                                             |
|--------------------------|--------------------------------------------|-----------------------------------------------------------------------------|
| `CombinationPolicy`      | `Assurance\DefaultCombinationPolicy`       | The classification of [Combination policy](assurance.md#combination-policy) |
| `ProofStore`             | `Proofs\SessionProofStore`                 | Proofs live in the Laravel session                                          |
| `RequirementPolicy`      | `Requirements\ConfiguredRequirementPolicy` | The composed requirement, or none when the first factor meets it all        |
| `IdentityRequirement`    | `Requirements\IdentityContractRequirement` | What the identity's `requiresAdditionalFactor()` returns                    |
| `TenantRequirement`      | `Requirements\NoTenantRequirement`         | A tenant asks for nothing                                                   |
| `ActiveTenantResolver`   | `Requirements\NoActiveTenant`              | No session has an active tenant                                             |
| `RequirementCheck`       | `Requirements\ProofRequirementCheck`       | One sign-in's proofs go to the combination policy                           |
| `FreshnessGate`          | `Requirements\ConfiguredFreshnessGate`     | The application's `freshness`, judged on the recorded proofs                |
| `FactorChangeGate`       | `Requirements\ConfiguredFactorChangeGate`  | A change rests on a fresh step-up, a first factor on a reauthentication     |
| `PendingSessionResolver` | `Context\NoPendingSessionResolver`         | No request carries a pending session                                        |
| `SubjectTypeResolver`    | `Context\IdentityContractSubjectType`      | A person is an identity whose `canHoldFactors()` is true                    |
| `ActiveStateResolver`    | `Context\IdentityContractActiveState`      | An identity is active when its `isMfaActive()` is true                      |
| `EventContextResolver`   | `Context\DefaultEventContextResolver`      | The identity and the caller's client; the dispatcher names the application  |
| `FirstFactorResolver`    | `Applications\DeclaredFirstFactorResolver` | The application's `first_factor`, dated at the Unix epoch                   |
| `Reauthenticator`        | `Seams\RefusingReauthenticator`            | Nothing proves the first factor again                                       |
| `SessionRevoker`         | `Proofs\GenerationSessionRevoker`          | The verification generation advances; other sessions verify again           |
| `SessionTransition`      | `Http\MiddlewareSessionTransition`         | Nothing to change: the `mfa` middleware is the gate                         |
| `ChallengeGateway`       | `Codes\PackageChallengeGateway`            | The package's own delivered codes                                           |
| `PendingCompletion`      | `Proofs\ProofStoreCompletion`              | A pending session's proof goes in the proof store                           |
| `StepUp`                 | `Proofs\ProofStoreCompletion`              | An active session's proof goes in the proof store                           |
| `PasskeyGateway`         | `Passkeys\UnavailablePasskeyGateway`       | Passkeys are unavailable                                                    |
| `LastFactorPolicy`       | `Lifecycle\RequiredFactorPolicy`           | The last acceptable factor stays while one is required                      |
| `SelfServiceRecovery`    | `Lifecycle\NoSelfServiceRecovery`          | None is offered; a person is reset by someone else                          |
| `SmsSender`              | `Codes\NullSmsSender`                      | Throws: the application binds one to enable `sms`                           |
| `EmailSender`            | `Codes\NullEmailSender`                    | Throws: the application binds one to enable `email`                         |
| `ApplicationResolver`    | None bound                                 | The application is the guard's name                                         |

A bound `ApplicationResolver` that serves several guards also implements `Contracts\GuardApplicationResolver`: its
`resolveForGuard()` is asked with the guard wherever one is known, the caller of a request and a sign-in or sign-out
alike, so a sign-in on a guard other than the default is bound to the application its caller is served on. Its kit,
`Concerns\GuardApplicationResolverTests`, is used beside `ApplicationResolverTests`, with the hooks
`guardApplicationResolver()`, `guardApplicationRequest()` and `applicationGuard()`.

The rest of `Contracts` is what the flows take rather than seams with a default: `Factor` and `EloquentFactor`,
`RecoveryCode` and `MultiFactorAuthenticatable` for your models, `FactorDriver`, `CodeDeliveryDriver` and
`ProvisioningDriver` for your drivers, and `MfaEvent`, which every event implements.

The refusing reauthenticator means an identity cannot add its first additional factor on an active session until
something proves its first factor again: bind a `Contracts\Reauthenticator` that asks the person for their password, for
example, and returns a `first_factor_reauthentication` proof bound to their current sign-in.

Every helper that acts for a person takes a `Context\CallerContext` first (see [The caller](helpers.md#the-caller)), and
no helper or seam is handed a request: `CallerContext::fromRequest()` asks the bound `PendingSessionResolver`'s
`fromRequest()`, and the actions ask its `revalidate()` under the identity's lock, with the pending session the caller
was served. A resolver that must read the credential again keeps it on the `PendingContext` it returns, as
`credential()`, which no dump or log of the context shows. On a pending session a helper serves only the action it needs
(`mfa.list_factors` for `factors()`, `factor()`, `offeredFactors()` and `recoveryCodeStatus()`, `mfa.send_code` for
`sendCode()`, `mfa.verify` for `verify()` and `requestAssertion()`), as the pending session's own identity; anything
else gets nothing, never the guard's user in its place. Starting, resending and cancelling an enrolment need
`mfa.start_bootstrap_enrollment`, and confirming one `mfa.confirm_bootstrap_enrollment`. Generating recovery codes,
renaming, preferring or removing a factor and `proofs()` serve active sessions only. A code is sent or checked only for
a binding that is exactly the caller's own, on its application and its session. A resolver reports a pending credential
that does not validate by throwing from `fromRequest()`, and a session that no longer stands by answering `null` from
`revalidate()`.

## Seams with an authentication layer

An adapter implements this package's seams with `laravel-authentication`, translating between the two packages' values:
this package references no class of that one, and that package's names are relative to
`SineMacula\Laravel\Authentication`. It lives in the application or in `laravel-iam`, never here. Results cross as
structured values, never reduced to `amr`. What each seam meets:

| This package                                                                          | `laravel-authentication`                                                                                                                                                                                                             |
|---------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `Contracts\RequirementPolicy`                                                         | `Contracts\AdditionalFactorPolicy::requirementFor()`, which the adapter answers with this policy                                                                                                                                     |
| `Contracts\TenantRequirement`                                                         | `Contracts\TenantAuthenticationPolicy::requirementFor()`; `Auth::sessions()->tenantPolicyChanged()` for a change outside a request                                                                                                   |
| `Contracts\RequirementCheck`                                                          | `Contracts\RequirementCheck::evaluate()`, which the adapter answers with this check                                                                                                                                                  |
| `Contracts\ActiveTenantResolver`                                                      | `Auth::tenant()`                                                                                                                                                                                                                     |
| `Contracts\PendingSessionResolver`                                                    | `Auth::sessions()->pending()`, answering a `Sessions\PendingSession`, from `fromRequest()` and again from `revalidate()` with the credential kept                                                                                    |
| `Enums\PendingAction`                                                                 | `Sessions\Enums\PendingAction`, with the same values                                                                                                                                                                                 |
| `Contracts\PendingCompletion`                                                         | `Auth::sessions()->satisfy()`, recording the proof's own `multifactor` from the result's `refreshesMultifactor`, with the caller's client translated to its own                                                                      |
| `Contracts\StepUp`                                                                    | `Auth::sessions()->stepUp()`, recording the proof's own `multifactor` from the result's `refreshesMultifactor`                                                                                                                       |
| `Contracts\FreshnessGate`                                                             | `Contracts\FreshnessPolicy::freshProof()` and `freshUntil()`                                                                                                                                                                         |
| `Contracts\FactorChangeGate`                                                          | `Auth::sessions()->factorChange()`, inside this package's transaction, after its locks                                                                                                                                               |
| `Contracts\Reauthenticator`                                                           | `Auth::sessions()->reauthenticate()`                                                                                                                                                                                                 |
| `Contracts\SessionRevoker`                                                            | `Auth::sessions()->factorRemoved()` with the factor, the application and the session, answered as judged, and `factorReset()` for a reset                                                                                            |
| `Contracts\SubjectTypeResolver`                                                       | `Contracts\MachineIdentity`                                                                                                                                                                                                          |
| `Contracts\ActiveStateResolver`                                                       | `Contracts\CanBeActive::isActive()`                                                                                                                                                                                                  |
| `Contracts\ApplicationResolver`                                                       | The session's `getGuard()`, from `Auth::session()`, and `Contracts\GuardApplicationResolver` for the guard of a sign-in or sign-out                                                                                                  |
| `Contracts\EventContextResolver`                                                      | The subject's `signInId` mapped to its session, principal and tenant; none when no sign-in is given                                                                                                                                  |
| `Contracts\PasskeyGateway`                                                            | `Auth::passkeys()->passkeys()`, `factorOptions()` and `verifyFactor()`                                                                                                                                                               |
| `Contracts\SmsSender`, `Contracts\EmailSender`                                        | `Contracts\OneTimeCodeSender`, bound to the same gateway: map `Codes\CodeMessage` and its `Enums\Purpose` into the gateway's own message                                                                                             |
| `Secrets\RevealedSecret`, `Secrets\SecretResponse`                                    | Nothing to bind: a secret it reveals is its own, so check its documentation for how it sends one uncached                                                                                                                            |
| `Contracts\ProofStore`, `Contracts\FirstFactorResolver`                               | `Requirements\RequirementSubject::proofs()` and `$firstFactor`, passed to `Contracts\RequirementCheck::evaluate()`, and `Contracts\FreshnessPolicy::freshProof()`. Needs a read of the session's proofs outside `evaluate()` as well |
| `Contracts\ChallengeGateway`, `Attempts\ChallengeCounters`                            | `Codes\CodeService::sendFactorCode()` and `verifyFactorCode()`; `Contracts\FactorCodeCounters`, answered with `isUsable()` and `report()`                                                                                            |
| `Contracts\SessionTransition`                                                         | `Auth::sessions()->factorChanged()` with the guard's current session, throwing when its id is not the change's `session`                                                                                                             |
| `Passkeys\PasskeyChangeGate`                                                          | `Contracts\PasskeyFactorGate::registering()` and `removing()`, answered with this gate inside its passkey transaction                                                                                                                |
| `Context\AuthenticationContextContributor`                                            | `Contracts\AuthenticationContextContributor::contribute()`, answered with `contributeFor()` from its `Context\ContributionSubject`                                                                                                   |
| `CombinationPolicy`, `IdentityRequirement`, `LastFactorPolicy`, `SelfServiceRecovery` | Nothing: these are this package's own                                                                                                                                                                                                |

A row that says what a seam needs names no method, as there is no public name to give here: check that package's own
documentation for it. Until the layer provides it, `Contracts\ProofStore` must still be rebound. The default keeps
proofs in the Laravel session, which a stateless layer does not have, so there is no sign-in and every verification
answers `not_found`.

`Contracts\SessionTransition::factorChanged()` is called after every factor change made on an active session, whether
or not this package finds the session short: a factor confirmed, a passkey registered as a factor, and a removal the
bound `SessionRevoker` did not judge the session after itself. So with the layer's `factorRemoved()` bound, a removal
never reaches it. It runs inside this package's transaction, after its locks and its writes, and is given a
`Requirements\SessionChange`:

| Property      | What it holds                                                                                    |
|---------------|--------------------------------------------------------------------------------------------------|
| `identity`    | The identity whose factors changed                                                               |
| `application` | The application acting                                                                           |
| `session`     | The sign-in the change was made on: the session id its proofs are bound to                       |
| `change`      | An `Enums\FactorChangeMade`: `factor_confirmed`, `passkey_factor_registered` or `factor_removed` |
| `factor`      | The factor the change was made to, as a `Factors\FactorSummary`                                  |
| `outstanding` | The requirement the session no longer meets, by this package's assessment, or `null`             |

The values of `Enums\FactorChangeMade` are those of the layer's `Factors\Enums\FactorChangeMade`, so an adapter maps one
with `from()`. The layer judges a session model, not an id, so the adapter passes the guard's current session. This
package checks that sign-in is still the request's under the identity's lock, so the two match. If they ever differ,
throw: returning without judging would let the change commit with no judgement of the session at all. `outstanding` is
information only: the layer judges the session against its own requirement. What `factorChanged()` returns, such as the
layer's `FactorChangeResult` carrying a pending session's new credential, comes back to the caller as the result's
`completion()`. A session the layer ended, or found no longer live, is an outcome to return, not a refusal. Refuse by
throwing, which rolls the whole change back.

> **Do not enable `passkey` over a layer whose register and remove paths do not call
> `Passkeys\PasskeyChangeGate`.** The gate has no default that can act for it, because the caller has to invoke it.
> Binding `Contracts\PasskeyGateway` over such a layer lets a passkey be removed with no step-up, last factor check or
> revocation, and an event after the fact cannot stand in for the gate.

How each seam behaves is in [the seam contracts design note](../design/seam-contracts.md).

## Challenge counters

Whoever owns a delivered factor's challenges (the package's own `Codes\PackageChallengeGateway`, or an authentication
layer's adapter behind `Contracts\ChallengeGateway`) reports to `Attempts\ChallengeCounters`, inside the transaction on
the storage connection that consumes the challenge, and answers with an `Attempts\ChallengeOutcome`, so the reason
reaches the caller:

```php
DB::transaction(function () use ($counters, $caller, $factor, $binding, $code): ChallengeOutcome {
    $admission = $counters->isUsable($caller, $factor, $binding);

    if (!$admission->isAdmitted()) {
        return ChallengeOutcome::refused($admission->reason, $admission->detail, $admission->lockedUntil);
    }

    $passed = $this->consume($binding, $code); // the owner's own challenge, locked and consumed here

    return $counters->report($caller, $factor, $binding, $passed)->passed
        ? ChallengeOutcome::passed()
        : ChallengeOutcome::failed(FailureReason::INVALID_CODE, 'The code did not match.');
});
```

`$caller` is the `Context\CallerContext` the gateway's `send()` or `verify()` was handed, or one the owner builds for
the identity with `CallerContext::forIdentity()`. A pending one carries the session's first factor, which the factor
must be accepted after. Both calls refuse with a `LogicException` outside a transaction, and with an
`InvalidArgumentException` for a caller that is nobody. `isUsable()` takes the identity's factor state lock,
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

Every path that registers or removes a passkey calls `Passkeys\PasskeyChangeGate` first, inside its own transaction on
the storage connection:

```php
DB::transaction(function () use ($gate, $caller, $credential, $properties, $binding): void {
    $this->storeCredential($credential); // the authentication layer's own write

    $result = $gate->registering($caller, new PasskeyRegistration($credential, $properties, $binding));

    // Reveal $result?->recoveryCodes only once this transaction has committed.
});
```

`$caller` is the `Context\CallerContext` of the person registering, read once at the layer's edge with
`CallerContext::fromRequest()` or built with `forIdentity()` or `forPending()`; `removing($caller, $credentialId)` takes
the same. `registering()` associates the passkey as a confirmed factor when the application enables `passkey`, after the
same checks an enrolment needs: the bound `Contracts\FactorChangeGate` allowing a further factor or the first one (by
default, a fresh step-up, or the first factor proved again), or the bootstrap path on a pending session that allows
`mfa.confirm_bootstrap_enrollment`; then the application's limits. It returns `null` when the application does not
enable the type, and recovery codes with the identity's first additional factor. On a pending session its proof then
goes to the bound `PendingCompletion`, and `verification` on the result holds what came back, whose refusal rolls your
registration back; reveal it only once your transaction has committed. On an active session the requirement is evaluated
again, the registration goes to the bound `SessionTransition`, and `completion()` on the result holds what came back,
whose refusal rolls it back too. `removing()` makes the checks of every removal: a sign-in the proof store knows of and
that has not changed under the lock, an active identity, the factor change gate allowing the removal (by default, a
fresh step-up made with another factor where the identity has one), and the last factor policy. It then tells the bound
`SessionRevoker` of the removal, which stops the identity's other sessions counting, and returns what the revoker
returned for your layer, such as the pending session's new credential when it judged the session itself, or else what
the bound `SessionTransition` returned. A refusal throws an `OperationRefusedException`; let it roll back your own
change, since catching it and committing breaks the gate.

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

A kit for a seam that is handed the caller asks for one through a hook, built as the seam would be handed it, with
`Context\CallerContext::forIdentity()` for an active session: `freshnessCaller()`, whose session the fresh gate must
find fresh for the fresh operation; `challengeCaller()`, the caller the challenged binding is for; and `stepUpCaller()`,
on an active session whose own result would be accepted. The session revoker's kit asks for the application the
identity's sessions are on, with `revokedApplication()`. The pending completion's kit hands every result through
`pendingCaller()`, the pending session's caller, which by default knows nothing of the client: a completion that judges
the client, such as one that checks a cookie-borne request is same-site, overrides it with a client carrying what that
check needs, so each refusal the kit asserts is the one it means. It also asks for `resultOfThePendingSession()`, a
successful result the completion accepts, which it must take from that caller and refuse from the same identity with no
pending session. The event context resolver's kit checks that a subject naming no sign-in, or one the resolver does not
know, leaves the session, principal and tenant unknown: override `arrangeServedEventSession()` to sign the identity in
through the authentication layer first, so a resolver that read the session being served is caught, and
`knownEventSignIn()` to return an application and a sign-in on it the resolver maps, whose session it must then name.

The kits check safety guarantees, not capabilities a default lacks: a refusing reauthenticator passes, and a revoker
passes when other sessions stop counting whether or not it ends them. The factor change gate's kit hands its hooks each
change and asks for the request from a session arranged fresh, or stale, for it; a removal stepped up only with the
factor it removes; and a change beyond the requirement the request carries. The session transition's kit hands its hook
each kind of change and asks for it made on a session arranged fresh for it, then judges it with a shortfall and
without. The proof store's kit begins a fixed sign-in id and voids proofs by advancing the verification generation,
which suits a store keeping its own sign-ins. A store over an authentication layer's sessions overrides
`proofStoreSignIn()` to sign the identity in through that layer and return the session's id, asked once a check, and
`voidProofStoreProofs()` to void them as that layer does on a reset. The sign-in may already hold the first factor the
layer recorded on signing in: each check counts against what it held when begun. A store whose proofs and sign-ins that
layer alone writes also overrides `arrangeProofStoreProof()` to record each proof a check needs through the layer (by
default through the store's `record()`), `endProofStoreSignIn()` to sign the identity out through it (by default
`forget()`), and `proofStoreFactor()` to enrol a factor the identity holds and return its id (by default
`ProofStoreContract::FACTOR`). The two new hooks are handed the store under test. Each check asserts that the proofs it
arranged count before it voids them or forgets their factor, so a hook that records nothing fails rather than passes.
The checks arrange a password first factor on top of what the sign-in holds: an adapter that cannot record one records
an equivalent proof, never skips it. Either way, a proof of a sign-in that is not current, or that the store cannot
find, is refused by throwing `Exceptions\ProofRefusedException`, as `ProofStore::record()` declares. Each check is a
static assertion on a `*Contract` class beside its trait, so a test can also call one directly. The kits need PHPUnit
and a database migrated with the package's tables, as any test of an adapter does.

