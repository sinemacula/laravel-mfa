# Proofs, assurance and requirements

The package describes what a session has proved, and what it must prove, with a small set of immutable values and
backed enums, and judges what the proofs add up to with a combination policy. The values hold no behaviour beyond
checking themselves: a value that contradicts itself is refused with an `InvalidArgumentException` when it is built, so
one that exists is always consistent. Every class name below is relative to `SineMacula\Laravel\Mfa`.

## Channels

A channel (`Assurance\Channel`) is where a proof travels or lives: its kind (`Enums\ChannelKind`) and, where it has
one, the destination or credential it names. Two proofs on the same channel are not independent, and a first factor
whose channel is unknown establishes no independence and no level.

```php
use SineMacula\Laravel\Mfa\Assurance\Channel;
use SineMacula\Laravel\Mfa\Enums\ChannelKind;

$phone    = new Channel(ChannelKind::SMS, '+447700900123');
$password = new Channel(ChannelKind::PASSWORD);
$unknown  = Channel::unknown();
```

A reference is never blank, and a password or an unknown channel takes none (`ChannelKind::takesReference()`). Those
two belong to first factors only: an enrolled factor always travels on a real channel (`ChannelKind::carriesFactor()`).

## Observed properties

`Assurance\ObservedProperties` holds what a proof actually observed: user presence, user verification, backup
eligibility, backup state and phishing resistance, each `true`, `false` or `null` for not observed, and key protection
(`Enums\KeyProtection`: `hardware` or `software`) or `null`. Nothing defaults to true, so a level, an `amr` value or a
context key is only ever derived from what was observed, never from a factor's type or from configuration. A TOTP code
observes nothing (`ObservedProperties::none()`); a passkey assertion reports what its authenticator data showed. A
credential observed backed up while observed as not eligible for backup is refused, as WebAuthn rules it out.

## Proofs

A proof (`Proofs\Proof`) is one verified authentication event:

| Part          | Holds                                                                                                  |
|---------------|--------------------------------------------------------------------------------------------------------|
| `kind`        | `Enums\ProofKind`: the first factor, a reauthentication with it, an additional factor, a recovery code |
| `method`      | The method proved, such as `password`, `totp`, `sms` or `passkey`                                      |
| `channel`     | Its `Channel`, or `null` for a recovery code; never a password or unknown one for an additional factor |
| `reference`   | The factor or credential it was made with; an additional factor always names its factor                |
| `properties`  | Its `ObservedProperties`                                                                               |
| `provedAt`    | When it was made, as a `CarbonImmutable`                                                               |
| `binding`     | A `Proofs\ProofBinding`: the identity's type and key, the application, the session and the purpose     |
| `generation`  | The identity's verification generation when it was made                                                |
| `challengeId` | The challenge it answered, when one was used                                                           |

The purpose (`Enums\Purpose`: `sign_in`, `reauthenticate`, `step_up`, `enrollment`) must suit the kind: a first factor
is proved at sign-in and a reauthentication with it carries `reauthenticate`. An additional factor may serve any
purpose, and a recovery code any but `enrollment`, since a recovery code cannot confirm an enrolment.

```php
use Carbon\CarbonImmutable;
use SineMacula\Laravel\Mfa\Assurance\Channel;
use SineMacula\Laravel\Mfa\Assurance\ObservedProperties;
use SineMacula\Laravel\Mfa\Enums\ChannelKind;
use SineMacula\Laravel\Mfa\Enums\ProofKind;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Proofs\Proof;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;

$proof = new Proof(
    kind: ProofKind::FIRST_FACTOR,
    method: 'password',
    channel: new Channel(ChannelKind::PASSWORD),
    reference: null,
    properties: ObservedProperties::none(),
    provedAt: CarbonImmutable::now(),
    binding: new ProofBinding($user->getMorphClass(), (string) $user->getKey(), 'admin', $request->session()->getId(), Purpose::SIGN_IN),
    generation: 0,
);
```

`toArray()` (and JSON) gives the proof with snake_case keys, its parts nested and its time as ISO-8601 to the
microsecond with its offset; `Proof::fromArray()` reads that form back. It refuses a required field that is missing
or of another type, and any field it does not know, so a mistyped key is never read as a missing one; a nullable
field (`channel`, `reference`, `challenge_id`, a channel's `reference`) may be left out and reads as `null`, and a
missing observed property reads as not observed. The serialised form holds the channel's full destination, so it is
for storing a proof, never for an event, a log or a response.

## Assurance levels

`Enums\AssuranceLevel` is the scale NIST SP 800-63B-4 defines: `aal1`, `aal2`, `aal3`, or `unclassified` when the
evidence cannot support a level. `meets($minimum)` is true for a level at or above the minimum, and never for
`unclassified`, which meets no level requirement.

## Requirements

A requirement (`Requirements\Requirement`) asks for any of four parts (`Enums\RequirementPart`), each with an optional
maximum age in seconds for the proof that satisfies it:

| Part                      | Asks for                                                                                |
|---------------------------|-----------------------------------------------------------------------------------------|
| `additional_verification` | An accepted additional verification, or a multi-factor first factor                     |
| `multifactor`             | Multifactor authentication: distinct factor categories, or a multi-factor authenticator |
| `minimum_level`           | At least the given assurance level                                                      |
| `phishing_resistance`     | A phishing-resistant proof                                                              |

```php
use SineMacula\Laravel\Mfa\Enums\AssuranceLevel;
use SineMacula\Laravel\Mfa\Requirements\Requirement;

$application = Requirement::none()->withAdditionalVerification();
$operation   = Requirement::none()->withMinimumLevel(AssuranceLevel::AAL2, maxAge: 900);

$effective = Requirement::strictest($application, $operation);
```

A maximum age is at least one second, and `unclassified` is no level to ask for. `Requirement::strictest()` composes
any number of requirements into the one a session meets only when it meets each of them: every part any of them asks
for, the highest minimum level, and each part's shortest maximum age, whatever the order. `asks()`, `maxAge()`,
`parts()` and `isEmpty()` read a requirement back. Its serialised form names each part asked for, with its `max_age`
and, for the minimum level, its `level`:

```php
['minimum_level' => ['level' => 'aal2', 'max_age' => 900]]
```

`Requirement::fromArray()` reads that form back and refuses an unknown part, or an unknown field within a part (a
`level` anywhere but the minimum level, or a mistyped `max_age`), so a mistyped one never weakens it.

## Evaluations

An evaluation (`Assurance\Evaluation`) is what a session's proofs add up to: whether the combination is `accepted` as
an additional verification, whether it is `multifactor`, the `level` it supports, whether it is `phishingResistant`,
whether it is `restricted` (it relies on a restricted authenticator, such as an SMS code), the RFC 8176 `amr` values it
reports, and the requirement parts it has `met` and left `unmet`. Accepted, multifactor and the level are separate
answers: an email code after a password is accepted without being multifactor. `meetsRequirement()` is true when no
part is unmet. An `amr` value is never blank or repeated, and no part is listed twice or both met and unmet.

An evaluation never reports more than its own answers allow, whichever combination policy built it:

- `additional_verification` is met only by an accepted or a multifactor combination;
- `multifactor` and `phishing_resistance` are met only when the combination is multifactor or phishing-resistant;
- `minimum_level` is never met at `unclassified`;
- `mfa` is reported only for a multifactor combination, and `mca` only for an accepted one that is not.

## Combination policy

The combination policy (`Contracts\CombinationPolicy`) answers two questions: whether a factor may follow a session's
first factor, and what the session's proofs add up to. The package binds `Assurance\DefaultCombinationPolicy`, which
classifies combinations as NIST SP 800-63B-4 does, from the channel each proof travelled on and the properties it
actually observed, never from a factor type's name or from configuration.

### Independent factors

`accepts($firstFactor, $channel)` is true when a factor on the channel may follow the first factor. A factor that
shares the first factor's channel is not independent of it, and is neither offered on the session nor verified on it:

- an SMS code to the phone the person signed in with, or an email code to the address they signed in with (compared
  without regard to case);
- the passkey that started the sign-in;
- a factor of the same kind as the first factor when either names no destination or credential, since independence
  cannot then be shown.

A first factor whose channel is unknown, a proof that is not a first factor or a reauthentication with one, and a
channel that cannot carry a factor (a password or an unknown one) accept nothing. A recovery code has no channel, so it
follows any known first factor.

```php
use SineMacula\Laravel\Mfa\Assurance\Channel;
use SineMacula\Laravel\Mfa\Contracts\CombinationPolicy;
use SineMacula\Laravel\Mfa\Enums\ChannelKind;

$policy = app(CombinationPolicy::class);

$policy->accepts($firstFactor, new Channel(ChannelKind::SMS, '+447700900456'));
```

### Classification

`evaluate($requirement, ...$proofs)` takes the session's proofs, the first factor's included, and returns an
`Evaluation`. Accepting an additional verification, achieving multifactor authentication and reaching a level are
separate answers:

| First factor                             | Further proof                                        | Accepted | Multifactor | Level                         |
|------------------------------------------|------------------------------------------------------|----------|-------------|-------------------------------|
| Password                                 | TOTP, passkey, recovery code                         | Yes      | Yes         | AAL2                          |
| Password                                 | SMS code                                             | Yes      | Yes         | AAL2, restricted              |
| Password                                 | Email code                                           | Yes      | No          | AAL1, from the password alone |
| Phone code                               | TOTP, recovery code, SMS code to a different phone   | Yes      | No          | AAL1, restricted              |
| Phone code                               | Email code                                           | Yes      | No          | AAL1, restricted              |
| Phone or email code                      | Passkey with observed user verification              | Yes      | Yes         | AAL2                          |
| Email code                               | TOTP, recovery code, SMS code                        | Yes      | No          | AAL1, from the further proof  |
| Phone code                               | SMS code to the same phone                           | No       | No          | AAL1, from the phone code     |
| Email code                               | Email code to the same address                       | No       | No          | Unclassified                  |
| Passkey with observed user verification  | None needed                                          | No       | Yes         | AAL2                          |
| External provider                        | Any enabled factor                                   | Yes      | No          | The further proof's own level |
| Unknown, or none                         | Any                                                  | No       | No          | Unclassified                  |

Behind the table are a few rules. A password is something the person knows; an SMS code, a TOTP code, a recovery code
and a passkey are something they have; a passkey whose assertion observed user verification is a multi-factor
authenticator on its own. Something known with something had, or a multi-factor authenticator, is multifactor
authentication and supports AAL2; anything else that is known or had supports AAL1. An email code is not an
out-of-band authenticator in NIST SP 800-63B-4 and establishes no level of its own, and an external provider's first
factor adds none, so the further proof's level applies (a passkey with observed user verification still reaches AAL2).
The default never reports AAL3, which needs hardware-bound keys it cannot see without attestation.

A combination is phishing-resistant when one of its proofs observed phishing resistance, as a passkey assertion does.
It is restricted when it relies on an SMS code, a restricted authenticator in NIST SP 800-63B-4: a phone code followed
by a passkey with observed user verification is not, since the passkey carries the level on its own, and neither is a
session that also reaches its level without the SMS code.

### `amr` values

The evaluation's `amr` values (RFC 8176) state only what happened. Each proof that counts adds its method's value,
first factor first: `pwd` for a password, `sms` for an SMS code, `otp` for a TOTP, email or recovery code, and `pop`
for a passkey; then `user` when it observed user presence, and `hwk` or `swk` when it observed how its key was
protected. `mfa` is added when the combination is multifactor, and `mca` when it is an accepted additional verification
that is not. An external provider's own methods are not repeated: an application that trusts them rebinds the policy.

### Requirements and maximum ages

Each part of the requirement is judged on its own. The session's proofs form combinations: the first factor alone,
each reauthentication with it alone, and the first factor followed by each further proof it accepts. A part is met when
one combination provides it on evidence no older than the part's maximum age:

- `additional_verification` is met by an accepted combination, or by a multi-factor first factor on its own;
- `multifactor`, `minimum_level` and `phishing_resistance` by a combination that is multifactor, reaches the level, or
  is phishing-resistant.

The evidence is the proof that completes the combination (the further proof, or the first factor or reauthentication
on its own), unless the first factor provides the part on its own and the further proof does not: the part then rests
on the first factor, and its age is the first factor's. A fresh weaker proof never refreshes an old stronger one.

So a fresh TOTP code after a password made hours ago meets a fifteen-minute `multifactor` part, since only the two
together are multifactor. A fresh TOTP or email code after a passkey sign-in made hours ago meets a fifteen-minute
`additional_verification` part, but not a fifteen-minute `multifactor`, `minimum_level` or `phishing_resistance` part,
which only the passkey provides. A fresh password reauthentication never stands in for an additional factor made hours
ago, and a passkey sign-in made hours ago no longer meets a part that asks for a fresh proof, though what it established
is still reported.

```php
use SineMacula\Laravel\Mfa\Enums\AssuranceLevel;
use SineMacula\Laravel\Mfa\Requirements\Requirement;

$evaluation = $policy->evaluate(
    Requirement::none()->withMinimumLevel(AssuranceLevel::AAL2, maxAge: 900),
    ...$proofs,
);

$evaluation->meetsRequirement();
```

### Failing closed

Nothing is accepted and no level is established when the proofs hold no first factor, more than one, or one whose
channel is unknown: the session cannot satisfy a requirement until its first factor is known. A proof bound to another
identity or application than the first factor counts for nothing, and so does a proof made before the first factor,
which an earlier sign-in left, or dated after the current time.

### Rebinding the policy

An application may bind its own policy, to be stricter than the default or to trust an external provider's reported
methods, in its own service provider. Decorating the default keeps its classification:

```php
use SineMacula\Laravel\Mfa\Assurance\Channel;
use SineMacula\Laravel\Mfa\Assurance\DefaultCombinationPolicy;
use SineMacula\Laravel\Mfa\Assurance\Evaluation;
use SineMacula\Laravel\Mfa\Contracts\CombinationPolicy;
use SineMacula\Laravel\Mfa\Enums\ChannelKind;
use SineMacula\Laravel\Mfa\Enums\ProofKind;
use SineMacula\Laravel\Mfa\Proofs\Proof;
use SineMacula\Laravel\Mfa\Requirements\Requirement;

final class NoSmsAfterPhoneCode implements CombinationPolicy
{
    public function __construct(private DefaultCombinationPolicy $default) {}

    public function accepts(Proof $firstFactor, Channel $factor): bool
    {
        if ($firstFactor->channel?->kind === ChannelKind::SMS && $factor->kind === ChannelKind::SMS) {
            return false;
        }

        return $this->default->accepts($firstFactor, $factor);
    }

    public function evaluate(Requirement $requirement, Proof ...$proofs): Evaluation
    {
        $firstFactors = array_filter($proofs, fn (Proof $proof): bool => $proof->kind === ProofKind::FIRST_FACTOR);
        $firstFactor  = count($firstFactors) === 1 ? reset($firstFactors) : null;

        $counted = array_filter($proofs, fn (Proof $proof): bool => $firstFactor === null
            || $proof->kind !== ProofKind::ADDITIONAL_FACTOR
            || $proof->channel === null
            || $this->accepts($firstFactor, $proof->channel));

        return $this->default->evaluate($requirement, ...$counted);
    }
}

$this->app->singleton(CombinationPolicy::class, NoSmsAfterPhoneCode::class);
```

A stricter `accepts()` must be applied in `evaluate()` too, as above: the default's `evaluate()` asks its own
`accepts()`, so without the filter a proof the stricter policy refuses, recorded before it was bound or passed in by an
adapter, would still count. The flows never offer or verify a factor the policy does not accept, so the filter guards
only against proofs that reached the session another way. Whatever policy is bound, an `Evaluation` refuses to report
more than its own answers allow (see [Evaluations](#evaluations)). How the default reaches its answers is described in
[the combination policy design note](../design/combination-policy.md).

## Verification results

A verification result (`Verification\VerificationResult`) is either `verified($proof, $evaluation)` or
`failed($reason, $detail)`, told apart by `isVerified()` and `isFailed()`. A failure carries a `FailureReason`, which
is what a caller may be told, and a detail, which stays in events and logs. A `locked` failure also carries the time
the lockout lifts (`lockedUntil`), and no other failure does.

Today `Mfa::verify()` answers `true` or `false`, and a failure is reported by the `MfaVerificationFailed` event, which
carries the same `FailureReason` as `$event->reason` and the detail as `$event->detail`: `locked`, `invalid_code`,
`expired` (for an expired code, and for a pending code without an expiry, told apart by the detail) and
`not_confirmed` (a factor with neither a pending code nor a secret).

## Stable names

These values are stable: listeners, stored proofs, configuration and the sibling packages depend on them.

| Enum                    | Values                                                                                                                                                                                                               |
|-------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `Enums\FailureReason`   | `invalid_code`, `expired`, `replayed`, `locked`, `not_confirmed`, `not_accepted`, `type_not_enabled`, `no_factor`, `not_found`, `sending_capped`, `mfa_enrollment_required`, `identity_inactive`, `machine_identity` |
| `Enums\ChannelKind`     | `password`, `sms`, `email`, `authenticator_app`, `passkey`, `external_provider`, `unknown`                                                                                                                           |
| `Enums\ProofKind`       | `first_factor`, `first_factor_reauthentication`, `additional_factor`, `recovery_code`                                                                                                                                |
| `Enums\Purpose`         | `sign_in`, `reauthenticate`, `step_up`, `enrollment`                                                                                                                                                                 |
| `Enums\KeyProtection`   | `hardware`, `software`                                                                                                                                                                                               |
| `Enums\AssuranceLevel`  | `aal1`, `aal2`, `aal3`, `unclassified`                                                                                                                                                                               |
| `Enums\RequirementPart` | `additional_verification`, `multifactor`, `minimum_level`, `phishing_resistance`                                                                                                                                     |
| `Enums\Operation`       | `mfa.add_factor`, `mfa.replace_factor`, `mfa.remove_factor`, `mfa.generate_recovery_codes`                                                                                                                           |
| `Enums\PendingAction`   | `mfa.list_factors`, `mfa.send_code`, `mfa.verify`, `mfa.start_bootstrap_enrollment`, `mfa.confirm_bootstrap_enrollment`                                                                                              |

A failure reason says what a caller may be told, not why in detail: a factor that does not exist and one that belongs
to someone else both answer `not_found`. Operations name the package's own step-up checks (adding a further factor,
replacing or removing one, generating recovery codes); an application names its own beside them. Pending actions name
what a pending session may do towards completing its sign-in, and `laravel-authentication` uses the same values.

How the values are built and why they refuse what they do is described in
[the assurance vocabulary design note](../design/assurance-vocabulary.md).
