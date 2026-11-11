# Requirements and step-up

What a sign-in must prove, and how fresh a session must be before a sensitive operation, are both requirements (see
[Proofs, assurance and requirements](assurance.md#requirements)) judged against the session's recorded proofs (see
[Recorded proofs](proofs.md)). Every class name below is relative to `SineMacula\Laravel\Mfa`.

## What a sign-in must prove

`Mfa::requirement()` returns the requirement the caller's sign-in on the caller's application must meet. It is empty
when nothing further is needed, and without an MFA-capable identity. The `mfa` middleware enforces it on the
routes that carry it (see [Route middleware](middleware.md)).

```php
use SineMacula\Laravel\Mfa\Context\CallerContext;
use SineMacula\Laravel\Mfa\Facades\Mfa;

$caller      = CallerContext::fromRequest($request); // see Helpers: The caller
$requirement = Mfa::requirement($caller);

$requirement->isEmpty();   // true when the sign-in needs nothing further
$requirement->parts();     // [RequirementPart::ADDITIONAL_VERIFICATION, ...]
```

The requirement is the strictest of these parts, so the same inputs always give the same answer. The identity's own
requirement and a re-enrolment obligation count in every application, whatever its mode:

| Source                                 | Asks for                                                                                     |
|----------------------------------------|----------------------------------------------------------------------------------------------|
| The application, `never` (the default) | Nothing                                                                                      |
| The application, `enrolled`            | An additional verification once the identity has a confirmed factor, nothing before          |
| The application, `always`              | An additional verification                                                                   |
| The identity                           | What `requiresAdditionalFactor()` returns (see [Identity models](identity-models.md))        |
| A re-enrolment obligation              | An additional verification while a reset obliges the identity to enrol again                 |
| The active tenant                      | What the bound `Contracts\TenantRequirement` answers, where `ActiveTenantResolver` names one |

An application nobody configured counts as `never`. Each part asks for its strictest: every part any source asks for,
the highest minimum level, and for each part the shortest maximum age. The mode is set per application (see
[Applications](configuration.md#applications)):

```php
'applications' => [
    'web'   => ['requirement' => 'enrolled', 'first_factor' => ['method' => 'password', 'channel' => 'password']],
    'admin' => ['requirement' => 'always', 'first_factor' => ['method' => 'password', 'channel' => 'password']],
],
```

The bound `Contracts\ActiveTenantResolver` says which tenant applies, from validated session context, as an opaque id:
never what a request merely claims, and never an event's descriptive context. Its default,
`Requirements\NoActiveTenant`, names none, so the tenant's requirement adds nothing until an adapter binds one, and a
sign-in has none before any principal or tenant is chosen. The same answer is used by `Mfa::requirement()` and whenever
a factor change evaluates the session again. The package never sees a tenant tree; the default
`Requirements\NoTenantRequirement` asks for nothing.

### A multi-factor first factor

After the first factor, `Contracts\RequirementPolicy` answers what the sign-in must still prove. Its default,
`Requirements\ConfiguredRequirementPolicy`, answers with the composed requirement, or with none when the first factor
meets all of it on its own: a passkey whose assertion verified the person meets an additional verification and
multifactor authentication, so it is asked for no further factor. Its level and age are judged like any proof's, so
the same passkey under a requirement for AAL3 leaves the whole requirement standing.

```php
use SineMacula\Laravel\Mfa\Contracts\RequirementPolicy;

$outstanding = app(RequirementPolicy::class)->requirementFor($user, 'web', $firstFactorProof);
```

## Step-up

A sensitive operation is named, and each name has a requirement and a maximum age for the proof that meets it, set per
application. `Mfa::isFresh()` answers whether the caller's session is fresh enough for it:

```php
use SineMacula\Laravel\Mfa\Facades\Mfa;

if (!Mfa::isFresh($caller, 'billing.change_plan')) {
    // ask the person to verify a factor again
}
```

The package's own operations (`mfa.add_factor`, `mfa.replace_factor`, `mfa.remove_factor` and
`mfa.generate_recovery_codes`) ask for an additional verification made within 900 seconds unless the application sets
them. Replacing a factor is enrolling then removing, so it asks `mfa.add_factor` and `mfa.remove_factor`;
`mfa.replace_factor` applies only where an application asks for it itself. An application names its own, and overrides
the package's, in its `freshness` block (see [Applications](configuration.md#applications)): seconds for an additional
verification within that age, or a requirement whose every part has a `max_age`.

The package's own changes to a person's factors are authorised by `Contracts\FactorChangeGate`, asked under the
identity's lock with the change (`Enums\FactorChange`), the sign-in it is made from, the factor a removal names and the
requirement the application configures for the operation. Its default, `Requirements\ConfiguredFactorChangeGate`,
judges each on this freshness: starting an enrolment for `mfa.add_factor`, and its grant lives no longer than the
answer (see [Enrolment](enrollment.md)); generating recovery codes for `mfa.generate_recovery_codes`; removing a factor
for `mfa.remove_factor`, on the proofs made without it (see [Factor lifecycle](lifecycle.md#the-step-up)). An
identity's first additional factor (`mfa.add_first_additional_factor`) rests instead on its first factor proved again
through the bound `Reauthenticator`, within five minutes, and no freshness is configured for it.

A caller may pass a requirement of its own; the stricter of it and the configured one applies, either alone when the
other is absent:

```php
use SineMacula\Laravel\Mfa\Enums\AssuranceLevel;
use SineMacula\Laravel\Mfa\Requirements\Requirement;

Mfa::isFresh($caller, 'mfa.remove_factor', Requirement::none()->withMinimumLevel(AssuranceLevel::AAL2, maxAge: 300));
```

Every part of a caller's requirement needs a maximum age of 1 to 86400 seconds: one without, or one longer, is refused
with an `InvalidArgumentException`. One that asks for nothing adds nothing. A name that is not an operation's is
answered `false` before the caller's requirement is checked, so it never throws.

A session is not fresh when:

- the operation has neither a configured requirement nor one of the caller's;
- the name is not an operation's: lower-case segments of letters, digits and underscores, each starting with a letter,
  separated by dots (`mfa.add_factor`, `billing.change_plan`);
- there is no MFA-capable identity, or no sign-in the proof store knows of, or no first factor on it;
- its proofs do not meet the requirement.

Each part is judged on the newest proof that meets it within its maximum age. A fresh weaker proof never refreshes an
old stronger one: a fresh email code does not bring back the AAL2 an old TOTP code reached. A fresh first factor never
stands in for an additional factor: signing in again, or reauthenticating with a password, renews nothing an
additional factor gave. Refreshing or regenerating the session renews nothing either: only a proof's own time counts.

A sign-in that a guard began through Laravel's `Login` event holds no first factor of its own. The default
`Contracts\FirstFactorResolver` then reports the one the application declares (`first_factor`), dated at the Unix epoch:
it tells the combination policy which channel a further factor must be independent of, but supplies no freshness, so the
session is fresh only once a further proof is. Without a declaration it is never fresh until the guard records a first
factor (`Proofs\GuardHooks::signedIn()`, see [Recorded proofs](proofs.md#custom-guards)) or a resolver of the
application's own reports one.

## Checking a session

`Contracts\RequirementCheck` answers whether a session's proofs meet any requirement, the same way at sign-in, for a
tenant and on step-up. Its default, `Requirements\ProofRequirementCheck`, keeps only the proofs of the sign-in their
one first factor began and hands them to the combination policy (see
[Combination policy](assurance.md#combination-policy)):

```php
use SineMacula\Laravel\Mfa\Contracts\RequirementCheck;
use SineMacula\Laravel\Mfa\Facades\Mfa;

$evaluation = app(RequirementCheck::class)->check($tenantRequirement, ...Mfa::proofs($caller));

$evaluation->meetsRequirement();
$evaluation->unmet;   // the parts still to prove
```

## Rebinding

Each part is a contract with a default, bound in the container; bind your own from a service provider:

| Contract               | Default                                    | Answers                                                   |
|------------------------|--------------------------------------------|-----------------------------------------------------------|
| `RequirementPolicy`    | `Requirements\ConfiguredRequirementPolicy` | What a sign-in must still prove after its first factor    |
| `IdentityRequirement`  | `Requirements\IdentityContractRequirement` | What the identity requires of its own sign-ins            |
| `ActiveTenantResolver` | `Requirements\NoActiveTenant`              | Which tenant applies to the session, if any               |
| `TenantRequirement`    | `Requirements\NoTenantRequirement`         | What an active tenant requires                            |
| `RequirementCheck`     | `Requirements\ProofRequirementCheck`       | Whether a session's proofs meet a requirement             |
| `FreshnessGate`        | `Requirements\ConfiguredFreshnessGate`     | Whether the session is fresh enough for a named operation |
| `FactorChangeGate`     | `Requirements\ConfiguredFactorChangeGate`  | Whether the session may make a change to its factors      |

`Mfa::isFresh()` hands the bound gate this package's own requirement for the operation as part of the caller's
requirement. A gate bound in place of the default, such as an adapter over an authentication layer's freshness check,
must apply the stricter of that and its own setting for the operation, never either alone, answer "not fresh" when it
has neither, and keep no state between calls. Its `requirement()` says what it holds a session to, which removing a
factor judges on the proofs made without that factor, so it must ask at least what the caller asks. It is asked with the
operation's own name (`mfa.add_factor`, never a name of the authentication layer's), so the layer's own setting for that
name is the one that applies; configure it there. It may be stricter than the package: a setting that takes only an
additional factor or a recovery code refuses a fresh passkey reauthentication that the package alone would accept.

A `FactorChangeGate` bound in place of the default, such as an adapter over an authentication layer's own factor-change
gate, replaces the package's judgement of those changes rather than adding to it, so the freshness gate is not asked for
them as well. It must hold the session to the requirement the request carries as well as its own policy, the stricter
applying; never let the factor a removal names count towards its own removal; give a grant an end in the future, as the
package refuses one without; and refuse by throwing an `OperationRefusedException`, which the caller receives as a
refusal. It is asked inside the identity's transaction, after the package's locks, so it may lock its own session row
there; it is never asked before the lock, nor when an enrolment is confirmed.

How each rule holds is in [the requirements and freshness design note](../design/requirements-and-freshness.md).
