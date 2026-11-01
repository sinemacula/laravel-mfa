# Capability Services

## Purpose

This note records how the package is organised: one namespace per capability, one service per capability behind the
`mfa` manager, and one `*Bindings` class per capability that registers its container wiring. The layout lets a
capability be replaced inside its own namespace (its service, its bindings, its tests) without touching the manager,
the provider or another capability.

## Invariants

- `MfaManager` is the factor driver registry (Laravel's `Manager`, so `Mfa::extend()`, `Mfa::driver()` and
  `getDefaultDriver()` behave as for any manager) and the single entry point the `Mfa` facade exposes. Every other
  public method is a one-line delegation to the service of its capability, with its arguments passed through and the
  service's answer returned unchanged.
- The manager resolves the service from the container on each call, so a service bound or rebound after the manager
  was resolved is the one used.
- Services resolve the seams a consumer rebinds (`MfaPolicy`, `ProofStore`, the event dispatcher and the
  configuration) from the container when they need them, never at construction, so a rebinding (`Event::fake()`, a
  store bound mid-test, a policy bound by a sibling package) reaches a service that is already resolved.
- The services act for the current identity: `Support\CurrentIdentity::resolve()`, which is `Auth::user()` on the
  default guard when it implements `MultiFactorAuthenticatable`. Without one, every service answers as it always has: no
  setup, no factors, no proofs, and nothing written or dispatched.
- The manager passes itself to the operations that run a factor through its driver (`challenge()`, `verify()`,
  `issueBackupCodes()`), and `Drivers\DriverResolver` resolves the driver from that registry. The drivers registered
  against the manager the call was made on are the ones a service runs, whether it is the `mfa` singleton or a manager
  built separately. A factor is only run through the driver it was registered against (`assertMatchesFactor()`), and
  only for its owner (`Factors\FactorOwnership`).
- No service keeps request state: the reads (`isSetup()`, `getFactors()`, `proofs()`) go to the identity, the
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
  (`EventBindings`, `FactorBindings`, `DriverBindings`, `CodeBindings`, `AssuranceBindings`, `RequirementBindings`,
  `ProofBindings`, `VerificationBindings`, `EnrollmentBindings`, `LifecycleBindings`, `RecoveryCodeBindings`), and at
  boot the middleware aliases (`HttpBindings`), the publishing tags and the configuration check
  (`Config\ConfigurationBindings`), which also refuses a configured model off the storage connection.
- The `mfa` factory builds the manager, then `DriverBindings::extend()` registers the TOTP, email and SMS drivers and
  `RecoveryCodeBindings::extend()` the backup-code driver, each built from the settings of its capability's block
  (`mfa.totp`, `mfa.codes`, `mfa.recovery_codes`), before the container applies any extender or resolving callback.
  The factory first checks the whole configuration (see the application configuration note).
- A call such as `Mfa::verify('totp', $factor, $code)` reaches `MfaManager::verify()`, which hands it to
  `Verification\VerificationService::verify()` with the manager as the driver registry. The service resolves the current
  identity, checks the driver and the owner, runs the driver, records the outcome on the factor, records the proof on
  the identity's sign-in through the bound proof store and dispatches the event.

## Failure / Edge Cases

- A capability service is `final` and internal; consumers extend the package through the seams (the contracts and
  `Mfa::extend()`), not by replacing a service. Binding a different object under a service's class reaches the manager,
  which is how the manager's delegation is tested, but is not a supported extension point.
- A driver registered under a shipped name that does not implement `FactorDriver` is refused when a service runs it
  (`LogicException`); a backup-code driver that is not `BackupCodeDriver` is refused when backup codes are issued.
- The default proof store is bound, not shared, so each resolution reads the session of the request at hand.

## Implementation Anchors

- `src/MfaManager.php`: the registry and the one-line delegations.
- `src/MfaServiceProvider.php`: `register()`, `registerManager()`, `boot()`, `offerPublishing()`.
- `src/*/*Bindings.php`: each capability's container wiring; `src/Drivers/DriverBindings.php` and
  `src/RecoveryCodes/RecoveryCodeBindings.php` also build the shipped drivers from config.
- `src/Requirements/RequirementService.php`, `src/Factors/FactorService.php`, `src/Proofs/ProofService.php`,
  `src/Verification/VerificationService.php`, `src/Enrollment/EnrollmentService.php`,
  `src/Lifecycle/LifecycleService.php`, `src/RecoveryCodes/RecoveryCodeService.php`: the capability services.
- `src/Factors/FactorOwnership.php`, `src/Drivers/DriverResolver.php`,
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
- `tests/Unit/Drivers/DriverResolverTest.php`
  `testResolvesFromTheRegistryPassedIn`
- `tests/Unit/Factors/FactorServiceTest.php`
  `testReadsTheFactorsOnEveryCall`
- `tests/Integration/CustomDriverExtensionTest.php`
  `testConsumerCanOverrideBuiltInTotpDriver`
- `tests/Integration/CustomDriverExtensionTest.php`
  `testContainerExtenderOverrideOfTotpWins`
- `tests/Integration/CustomDriverExtensionTest.php`
  `testResolvingCallbackOverrideOfTotpWins`
- `tests/Integration/CustomDriverExtensionTest.php`
  `testASeparateManagerVerifiesThroughItsOwnDriver`

## Change Triggers

Update this note when any of the following change:

- a capability gains, loses or moves a namespace, a service or a `*Bindings` class
- the manager does more than delegate, or a method moves to another capability's service
- the rule that services resolve the seams consumers rebind when they need them, not at construction
- how or when the shipped drivers are registered against the manager, or which registry a service runs drivers from
- a service starts keeping request state between calls
