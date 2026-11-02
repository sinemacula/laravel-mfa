# Requirements and Freshness

## Purpose

This note records how the package decides what a sign-in must prove after its first factor, how that requirement is
composed from its sources, how a session's proofs are checked against a requirement, and how the freshness of a session
is judged before a sensitive operation. Every answer is worked out from the session's recorded proofs (see
[Proof Store and Sign-Ins](proof-store.md)) by the combination policy (see [Combination Policy](combination-policy.md));
nothing is stored in their place.

## Invariants

- A sign-in's requirement is `Requirement::strictest()` of its parts, so the same inputs give the same answer in any
  order (`Requirements\RequirementService::requirementFor()`):
  - the application's configured mode (`mfa.applications.{name}.requirement`): nothing for `never` and for an
    application nobody configured; an additional verification of any age for `always`; and for `enrolled` an
    additional verification once the identity has a confirmed factor (`isMfaEnabled()`), nothing before;
  - the identity's own requirement, from the bound `Contracts\IdentityRequirement`, whose default
    (`Requirements\IdentityContractRequirement`) is the model's `requiresAdditionalFactor()`, nothing for `null`;
  - an additional verification while the identity's re-enrolment obligation (`reenrollment_required` on its row in the
    identity states table) is set, in every application, read from the write connection
    (`Requirements\ReenrollmentObligation`);
  - where the bound `Contracts\ActiveTenantResolver` names a tenant, from validated session context, the tenant's
    requirement, from the bound `Contracts\TenantRequirement`, whose default (`Requirements\NoTenantRequirement`) asks
    for nothing. The resolver's default (`Requirements\NoActiveTenant`) names none, and a session has none before any
    principal is chosen, so nothing is added at the identity level. `EventContextResolver`'s `tenant_id` is descriptive
    metadata and plays no part: omitted audit data must never drop a requirement.
- `Mfa::requirement()` is the current identity's sign-in requirement on the current application (the application a
  bound `ApplicationResolver` names, or the default guard's name), with the active tenant's where one applies; it is
  empty without an MFA-capable identity. The `mfa` middleware enforces nothing when it is empty.
- The default `Contracts\RequirementPolicy`, `Requirements\ConfiguredRequirementPolicy`, answers with that requirement,
  or with none when the first factor meets all of it on its own, as a passkey whose assertion observed user verification
  meets an additional verification. The first factor is judged by the bound `RequirementCheck` like any proof, so one
  too old for a part, or below a minimum level, leaves the whole requirement standing; a proof that is not a first
  factor of the identity on the application suppresses nothing.
- The default `Contracts\RequirementCheck`, `Requirements\ProofRequirementCheck`, hands the bound `CombinationPolicy`
  only the proofs of one sign-in: those bound to the same session as the proofs' one first factor. With no first factor,
  or more than one, it hands none, so nothing but an empty requirement is met. The policy meets a part when one
  combination provides it on evidence within the part's maximum age, which for a yes or no answer is the newest proof
  meeting the part: there is no separate selection of the newest proof.
- An operation's requirement is configured per application in `freshness` (`ApplicationSettings::freshness()`): seconds
  for an additional verification within that age, or a serialised requirement asking for at least one part, each with a
  `max_age` of 1 to 86400 seconds. The package's own operations (`Enums\Operation`) default to an additional
  verification within 900 seconds; an entry replaces the default whole. Names are the block's keys, read whole, and must
  match `Operation::NAME_PATTERN`, the pattern authentication's operation names use.
- The requirement a step-up must meet (`Requirements\OperationRequirements::effective()`) is the strictest of the
  configured one and the caller's, either alone when the other is absent, and none with neither or for a name that does
  not match the pattern. A name that does not match is answered first, whatever the caller asks, so it never throws.
  Otherwise a caller's requirement that asks for nothing adds nothing; one with a part that carries no maximum age, or
  one longer than 86400 seconds, is refused with an `InvalidArgumentException` before the configuration is read
  (`Requirements\FreshnessBounds`), so whatever judges the step-up always has a bounded age.
- The default `Contracts\FreshnessGate`, `Requirements\ConfiguredFreshnessGate`, answers `false` with no requirement,
  no MFA-capable identity, no sign-in the proof store knows of on the application, or no first factor; otherwise it
  answers whether the bound `RequirementCheck` finds the sign-in's recorded proofs meet the requirement. Freshness adds
  none of the sign-in's own parts.
- The gate takes the first factor from the proof store. Only when the store holds none is the bound
  `FirstFactorResolver` asked, and its proof counts only when it is a first factor of the identity on the application,
  bound to the current sign-in, made under the identity's current verification generation and not after now. The
  default resolver reads the application's `first_factor` declaration and dates it at the Unix epoch, so it establishes
  the channel a further factor must be independent of but never meets a part with a maximum age on its own.
- `Mfa::isFresh($operation, $requirement)` asks the bound gate with the strictest of this package's setting for the
  operation and the requirement given as the caller's requirement, after answering `false` for a name that does not
  match the pattern and refusing an unbounded one. A gate an adapter binds over an authentication layer's freshness
  check therefore always receives this package's setting and must apply the stricter of it and its own; the default
  gate sees the same setting twice, which changes nothing.
- Refreshing never renews freshness: only a proof's `provedAt` counts. Regenerating or migrating the Laravel session
  keeps the records and their times, a first-factor reauthentication renews only what it provides on its own, and
  nothing but a successful proof records a proof.
- Every default keeps no state between calls and resolves the configuration, the store and its collaborators on each
  call, and each is built when it is asked for, on the application serving at the time.

## Success Path

1. The `mfa` middleware asks `Mfa::requirement()`; with an empty requirement the request passes.
2. An adapter's sign-in asks `RequirementPolicy::requirementFor($identity, $application, $firstFactor)` and puts `mfa`
   in the pending session's `requires` when the answer is not empty.
3. Where a tenant becomes active, the adapter names it through `ActiveTenantResolver`; the tenant's requirement is then
   part of what the session is held to, and of what a factor change evaluates it against again.
4. Before a sensitive operation, the package or the application asks `Mfa::isFresh('mfa.remove_factor')`; the gate
   reads the sign-in's proofs and the check judges them against the operation's requirement.

## Failure / Edge Cases

- A session that signed in through Laravel's `Login` event holds a sign-in with no first factor, so it is never fresh
  until a first factor is recorded (`GuardHooks::signedIn()`), the application declares one, or a `FirstFactorResolver`
  of its own reports one.
- A fresh password reauthentication after an old TOTP code does not meet a fresh AAL2 or a fresh additional
  verification, though it meets a fresh AAL1 on its own. A fresh email code after an old TOTP code does not meet a fresh
  multifactor part.
- A fresh reauthentication with a passkey whose assertion verified the person meets a fresh additional verification,
  as any multi-factor first factor does. A bound gate is asked with the operation's own name and may be stricter: an
  authentication layer's setting for `mfa.add_factor` that takes only an additional factor or a recovery code, as its
  `factor_change` operation does, refuses it. Its `factor_change` setting does not apply to the package's operations
  unless the adapter applies it as well.
- An external provider's reauthentication, mapped as a first-factor reauthentication on an `external_provider` channel
  that observed nothing (see [Seam Contracts](seam-contracts.md)), meets no additional verification and no level.
- A name in capitals, with a hyphen, an empty segment or a trailing newline is not an operation's: it is never fresh,
  and the configuration refuses it as a `freshness` key.
- A well-formed name nobody configures is judged on the caller's requirement alone, as authentication's per-operation
  check judges it, so a bound gate is still asked with a name only it configures. A misspelt name therefore loses the
  setting configured for the name it meant, though never the caller's own requirement; the package's operations are
  named by `Enums\Operation` for that reason.
- A caller passing the usual unbounded sign-in requirement to `isFresh()` is refused; it passes a bounded one, or checks
  the sign-in requirement separately.
- A malformed `freshness` entry fails closed with an `InvalidArgumentException` naming the key when it is read, and the
  configuration check reports it under the application.
- An identity whose key is neither a non-empty string nor an integer cannot have its obligation read, so its
  requirement is refused with `UnsupportedIdentifierException` rather than answered as empty.

## How Long An Answer Lasts

- `FreshnessGate::freshUntil()` asks what `isFresh()` asks and says how long the answer lasts: the instant the session
  stops being fresh on the proofs it holds now, `null` when it is not fresh or the gate cannot say, so a grant taken
  from it lives no longer than the proof that authorised it (see [Enrolment](enrollment.md)). `Evaluation::$metUntil` is
  how the default gate reads it: for each part with a maximum age, the latest evidence time among the combinations
  providing it plus that age, and the earliest across the parts.
- The default gate answers for the person the request serves and nobody else: a pending session, a guest, a machine and
  an inactive identity are not fresh for any operation, and no helper's `isFresh()` or `freshUntil()` reads the guard's
  user in their place.
- The `mfa` middleware judges this requirement, with any level or operation its route asks (see
  [Route Gate](route-gate.md)).

## Seams Left

- A reset sets the re-enrolment obligation as it states (`ReenrollmentObligation::record()`, see
  [Factor Lifecycle](factor-lifecycle.md)); confirming a factor ends it (`ReenrollmentObligation::end()`, see
  [Enrolment](enrollment.md)).
- Starting an enrolment and the passkey change gate ask the gate for `mfa.add_factor`, the gate for `mfa.remove_factor`
  (see [Passkeys](passkeys.md)), removing a factor for `mfa.remove_factor` and issuing recovery codes for
  `mfa.generate_recovery_codes`.

## Implementation Anchors

- `src/Contracts/RequirementPolicy.php`, `IdentityRequirement.php`, `ActiveTenantResolver.php`,
  `TenantRequirement.php`, `RequirementCheck.php`,
  `FreshnessGate.php`.
- `src/Requirements/RequirementService.php`, `ConfiguredRequirementPolicy.php`, `IdentityContractRequirement.php`,
  `NoActiveTenant.php`, `NoTenantRequirement.php`, `ReenrollmentObligation.php`, `ProofRequirementCheck.php`,
  `ConfiguredFreshnessGate.php`,
  `OperationRequirements.php`, `FreshnessBounds.php`, `RequirementBindings.php`.
- `src/Database/IdentityStateRow.php`, the identity's row the obligation is read from, shared with
  `Proofs\VerificationGeneration`.
- `src/Applications/ApplicationSettings.php` (`requirement()`, `freshness()`, `freshnessFor()`),
  `src/Enums/Operation.php` (`isName()`).
- `src/MfaManager.php` (`requirement()`, `isFresh()`), `src/Http/Middleware/EnsureMfaRequirementIsMet.php`.

## Authoritative Tests

- `tests/Unit/Requirements/RequirementServiceTest.php`: the composition table, every mode crossed with the identity's
  requirement, the obligation and a tenant; the order of the parts; `isFresh()` handing the gate this package's setting.
- `tests/Unit/Requirements/ProofRequirementCheckTest.php`: the newest proof meeting each part, another sign-in's proofs,
  an external reauthentication.
- `tests/Unit/Requirements/ConfiguredRequirementPolicyTest.php`: a multi-factor first factor meeting the requirement.
- `tests/Unit/Requirements/ConfiguredFreshnessGateTest.php`: an unknown operation, the stricter setting both ways, a
  session with no record, a fresh weaker proof, a fresh first factor, a refreshed session, a resolved first factor.
- `tests/Unit/Requirements/OperationRequirementsTest.php`, `FreshnessBoundsTest.php`,
  `tests/Unit/Applications/ApplicationSettingsTest.php`, `tests/Unit/Enums/OperationTest.php`: configuration, names and
  bounds.
- `tests/Integration/Database/WriteConnectionReadTest.php`: the obligation read from the write connection.

## Change Triggers

- Adding a source to the sign-in requirement, or composing it other than by `Requirement::strictest()`.
- Letting a fresh first factor, a reauthentication or a refreshed session stand in for an additional factor.
- Judging freshness on anything but a proof's own time, or reading a proof of another sign-in.
- Accepting an unbounded caller requirement, or an operation name outside the pattern.
- Adding a proof kind for an external reauthentication instead of mapping it.
