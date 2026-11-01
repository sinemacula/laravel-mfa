# Proofs, assurance and requirements

The package describes what a session has proved, and what it must prove, with a small set of immutable values and
backed enums. They hold no behaviour beyond checking themselves: a value that contradicts itself is refused with an
`InvalidArgumentException` when it is built, so one that exists is always consistent. Every class name below is
relative to `SineMacula\Laravel\Mfa`.

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
