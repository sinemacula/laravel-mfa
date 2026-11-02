# Capability Services

## Purpose

This note records how the package is organised: one namespace per capability, one service per capability behind the
`mfa` manager, and one `*Bindings` class per capability that registers its container wiring. The layout lets a
capability be replaced inside its own namespace (its service, its bindings, its tests) without touching the manager,
the provider or another capability.

## Invariants

- `MfaManager` is the factor driver registry (Laravel's `Manager`, so `Mfa::extend()`, `Mfa::driver()` and
  `getDefaultDriver()` take the names they take on any manager) and the single entry point the `Mfa` facade exposes.
  Every other public method is a one-line delegation to the service of its capability, with its arguments passed
  through and the service's answer returned unchanged.
- The surface is flat: one method per flow, listed in [Helpers](../guides/helpers.md), with the facade annotating
  exactly those methods and a test holding the two equal. An annotation is documentation, not an allowlist:
  `getDrivers()`, `getContainer()` and `forgetDrivers()` stay callable as inherited infrastructure.
- The manager holds nothing a request gave it. It declares no property, resolves every service from
  `Container::getInstance()` rather than `$this->container`, so a service bound or rebound after the manager was
  resolved is the one used and a sandbox's service is the one answering, and `setContainer()` refuses. `$config` stays
  the one the constructor read, which nothing reads.
- No driver is cached: `driver()` builds on every call, keeping Laravel's normalisation of the name, and
  `callCustomCreator()` hands a creator the current application. `Manager::$drivers` stays empty for the manager's whole
  life, and `extend()` needs no eviction, so the most recent registration wins however late it is made. Each shipped
  factory takes the container it is handed and captures nothing. A driver keeps no state between calls.
  `Mfa::driver('totp') === Mfa::driver('totp')` is not true.
- A method the manager does not declare is refused (`BadMethodCallException`, naming the method and no argument).
  Laravel's `Manager::__call` would forward it to the default driver, reaching a raw check outside attempts, proofs and
  events.
- A helper a person can be refused by answers with a value holding the reason, never a plain exception
  (`RecoveryCodes\RecoveryCodeGeneration`, `Passkeys\AssertionRequest`, as `Factors\FactorChange` does). On
  `generateRecoveryCodes()` and `requestAssertion()`, a refusal becomes a value only when marked as the package's own
  (`OperationRefusedException::byPackage()`): a seam's stays an exception. The mark says who refused, not when, so
  nothing that runs after a commit is converted. The other helpers do not read it: a seam's refusal inside what they
  guard is their reason.
- Services resolve the seams a consumer rebinds (`FreshnessGate`, `ProofStore`, the event dispatcher and the
  configuration) from the container when they need them, never at construction, so a rebinding (`Event::fake()`, a
  store bound mid-test, a policy bound by a sibling package) reaches a service that is already resolved.
- The services act for the current identity: `Support\CurrentIdentity::resolve()`, which is `Auth::user()` on the
  default guard when it implements `MultiFactorAuthenticatable`. Without one, every service answers as it always has: no
  setup, no factors, no proofs, and nothing written or dispatched.
- A factor runs through the driver of its type, resolved by `Drivers\DriverResolver` from the `mfa` manager the
  container holds. Recovery codes are not a factor and have no driver. A factor
  is only looked up within the identity the request serves (`Factors\OperationGuard`).
- No service keeps request state: the reads (`factors()`, `factor()`, `proofs()`) go to the identity, the
  database or the bound proof store on every call, so a singleton service never carries one request's identity or
  factors into the next.
- Each capability registers its container wiring in its own `*Bindings` class, which the provider calls: the
  capability's service as a singleton and the defaults for the seams it owns. The capabilities that ship drivers also
  build them, and the provider's `mfa` factory registers them against the manager through the same `extend()` API a
  consumer uses, before it returns the manager. The shipped drivers therefore exist before the container runs any
  extender or resolving callback on `mfa`, so a consumer's registration of the same name replaces them however it is
  made: `Mfa::extend()`, a container extender or a resolving callback.
- The public surface is unchanged by the layout: the manager's and the facade's method names, the configuration keys,
  the events and the middleware aliases are the same whichever service answers them.

## Success Path

- The provider registers the configuration, the `mfa` manager singleton and each capability's bindings
  (`EventBindings`, `ContextBindings`, `SeamBindings`, `FactorBindings`, `DriverBindings`, `CodeBindings`,
  `AssuranceBindings`, `RequirementBindings`, `ProofBindings`, `VerificationBindings`, `EnrollmentBindings`,
  `LifecycleBindings`, `RecoveryCodeBindings`, `PasskeyBindings`, and the session transition of `HttpBindings`), and at
  boot the middleware aliases (`HttpBindings`), the publishing tags and the configuration check
  (`Config\ConfigurationBindings`), which also refuses a configured model off the storage connection.
- The `mfa` factory builds the manager, then `DriverBindings::extend()` registers the TOTP, email, SMS and passkey
  drivers, each built from the settings of its capability's block (`mfa.totp`, `mfa.codes`), before the container
  applies any extender or resolving callback.
  The factory first checks the whole configuration (see the application configuration note).
- A call such as `Mfa::verify(Submission::factor($id, $code))` reaches `MfaManager::verify()`, which hands it to
  `Verification\VerificationService::verify()`. The service resolves who the request serves, guards the factor, checks
  and counts the code under the identity's lock, hands the result to the completion seam and queues the events (see
  [Verification Lifecycle and Events](verification-lifecycle-and-events.md)).

## Failure / Edge Cases

- A capability service is `final` and internal; consumers extend the package through the seams (the contracts and
  `Mfa::extend()`), not by replacing a service. Binding a different object under a service's class reaches the manager,
  which is how the manager's delegation is tested, but is not a supported extension point.
- A driver registered under a shipped name that does not implement `FactorDriver` is refused when a service runs it
  (`LogicException`).
- The default proof store is bound, not shared, so each resolution reads the session of the request at hand.

## Implementation Anchors

- `src/MfaManager.php`: the registry and the one-line delegations.
- `src/MfaServiceProvider.php`: `register()`, `registerManager()`, `boot()`, `offerPublishing()`.
- `src/*/*Bindings.php`: each capability's container wiring; `src/Drivers/DriverBindings.php` also builds the shipped
  drivers from config.
- `src/Requirements/RequirementService.php`, `src/Factors/FactorService.php`, `src/Proofs/ProofService.php`,
  `src/Verification/VerificationService.php`, `src/Enrollment/EnrollmentService.php` (with `EnrollmentStarter.php` and
  `EnrollmentConfirmer.php` behind it),
  `src/Lifecycle/LifecycleService.php`, `src/RecoveryCodes/RecoveryCodeService.php`: the capability services.
- `src/Drivers/DriverResolver.php`,
  `src/Support/CurrentIdentity.php`, `src/Config/IntegerSetting.php`: what the services share.

## Authoritative Tests

- `tests/Unit/MfaManagerTest.php`
  `testMethodDelegatesToItsCapabilityService`
- `tests/Unit/MfaServiceProviderTest.php`
  `testRegistersEachCapabilitysBindings`
- `tests/Unit/MfaServiceProviderTest.php`
  `testRegistersTheShippedDrivers`
- `tests/Unit/Drivers/DriverBindingsTest.php`
  `testExtendRegistersDriversThatReadTheConfig`
- `tests/Unit/Drivers/DriverResolverTest.php`
  `testResolvesTheManagersDriver`
- `tests/Unit/MfaManagerTest.php`
  `testAnUndeclaredMethodIsRefusedAndNeverReachesTheDriver`
- `tests/Unit/MfaManagerLongRunningTest.php`
  `testADelegationAnswersFromTheCurrentApplication`
- `tests/Unit/MfaManagerLongRunningTest.php`
  `testShippedDriversAreBuiltFromTheCurrentApplication`
- `tests/Unit/MfaManagerLongRunningTest.php`
  `testTheManagersOwnFieldsKeepNothingOfACopy`
- `tests/Unit/Facades/MfaTest.php`
  `testTheFacadeAnnotatesEveryManagerMethodAsDeclared`
- `tests/Unit/Factors/FactorServiceTest.php`
  `testReadsTheFactorsOnEveryCall`
- `tests/Integration/CustomDriverExtensionTest.php`
  `testConsumerCanOverrideBuiltInTotpDriver`
- `tests/Integration/CustomDriverExtensionTest.php`
  `testContainerExtenderOverrideOfTotpWins`
- `tests/Integration/CustomDriverExtensionTest.php`
  `testResolvingCallbackOverrideOfTotpWins`

## Change Triggers

Update this note when any of the following change:

- a capability gains, loses or moves a namespace, a service or a `*Bindings` class
- the manager does more than delegate, keeps anything, or a method moves to another capability's service
- the facade's surface changes
- the rule that services resolve the seams consumers rebind when they need them, not at construction
- how or when the shipped drivers are registered against the manager, whether a driver is cached, or which manager a
  service runs drivers from
- a service starts keeping request state between calls
