# Enrolment

A factor is enrolled in two steps. Starting makes a pending factor and a grant that may confirm it; confirming takes the
first valid code, in the same session, within the grant, and makes the factor confirmed. A pending factor is not usable
and is not offered. Every class name below is relative to `SineMacula\Laravel\Mfa`.

A passkey is the exception: it becomes a factor through its registration, which the authentication layer passes through
`Passkeys\PasskeyChangeGate` (see [Extending](extending.md#passkeys)). Starting an enrolment of the `passkey` type is
refused as `not_accepted`.

## The flow

```php
use SineMacula\Laravel\Mfa\Enrollment\EnrollmentRequest;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\Secrets\SecretResponse;

$start = Mfa::startEnrollment(EnrollmentRequest::totp($user->email, label: 'My phone'));

if (! $start->hasStarted()) {
    return response()->json(['reason' => $start->reason->value], 422);
}

return SecretResponse::json([
    'factor'           => $start->factor,
    'grant'            => $start->grant,
    'expires_at'       => $start->expiresAt,
    'secret'           => $start->secret,
    'provisioning_uri' => $start->provisioningUri,
]);
```

The grant, the secret and the provisioning URI are returned here and never again, as `Secrets\RevealedSecret` values:
send them with `SecretResponse::json()` on a route with the `mfa.no-store` middleware (see [Secrets](secrets.md)). A
person who loses them starts again. Cookie-authenticated routes need CSRF protection (see
[CSRF protection](middleware.md#csrf-protection)). The person's authenticator app reads the URI from a QR code you
render, and shows a code:

```php
$confirmation = Mfa::confirmEnrollment($request->string('grant')->toString(), $request->string('code')->toString());

if (! $confirmation->isConfirmed()) {
    return response()->json(['reason' => $confirmation->reason->value], 422);
}

return SecretResponse::json([
    'factor'         => $confirmation->factor,
    'recovery_codes' => $confirmation->recoveryCodes,
]);
```

A delivered type names the destination to prove instead, and its first code goes out as the enrolment starts:

```php
Mfa::startEnrollment(EnrollmentRequest::delivered('email', $request->string('email')->toString()));
Mfa::startEnrollment(EnrollmentRequest::delivered('sms', '+44 7700 900123', label: 'Work phone'));
Mfa::startEnrollment(EnrollmentRequest::provisioned('your_app_type', $request->user()->email));
Mfa::startEnrollment(EnrollmentRequest::of('your_own_type'));
```

`provisioned()` is for your own type whose driver implements `Contracts\ProvisioningDriver`: it starts as TOTP does,
under the account name and optional issuer the app shows.

`EnrollmentRequest::totp()` also takes the `issuer` the app shows. Without one, `mfa.totp.issuer` applies, or the
application's name. Neither the issuer nor the account name may hold a colon, and a label is trimmed, a blank one being
none and one over 255 characters refused, so validate what a person types first.

| Call                                    | Answers                                                             |
|-----------------------------------------|---------------------------------------------------------------------|
| `Mfa::startEnrollment($request)`        | `Enrollment\EnrollmentStart`, with `hasStarted()`                   |
| `Mfa::confirmEnrollment($grant, $code)` | `Enrollment\EnrollmentConfirmation`, with `isConfirmed()`           |
| `Mfa::resendEnrollmentCode($grant)`     | `Codes\SendResult`, renewing nothing                                |
| `Mfa::cancelEnrollment($grant)`         | `true` when it was cancelled, `false` for a grant that is not yours |
| `Mfa::renameFactor($factorId, $label)`  | `Factors\FactorChange`, with `wasMade()`                            |
| `Mfa::setPreferredFactor($factorId)`    | `Factors\FactorChange`, with `wasMade()`                            |

A grant is taken as a `RevealedSecret` or as the string revealed from it. A refusal is a result carrying a reason a
caller may be told, since `not_fresh` is an ordinary path; only misuse, a storage failure or a delivery failure throws,
and a pending credential that does not validate still throws through your resolver.

## What authorises a start

| The session is                                  | It needs                                                                                                                                                 |
|-------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------|
| Active, and the identity has a confirmed factor | The bound `Contracts\FactorChangeGate` allowing `mfa.add_factor`: by default, a step-up fresh for it (see [Requirements](requirements.md))               |
| Active, and the identity has none               | The gate allowing `mfa.add_first_additional_factor`: by default, the first factor proved again within five minutes through `Contracts\Reauthenticator`   |
| Pending                                         | The bootstrap path: the credential allows the action, `bootstrap.enabled` and `bootstrap.types` allow the type, and the identity has no confirmed factor |

Then the application's limits apply (see [Applications](configuration.md#applications)). They count only factors
enrolled through this application: `limits.confirmed`, `limits.confirmed_per_type` and `limits.pending`.

Starting again replaces. Any pending factor of the same type through this application is discarded, from any session,
with its secret and its grant, and expired ones through this application go with it. Its delivered codes stay: the send
caps count what a destination and an identity were sent, and a new first code waits out the cooldown since the last
enrolment code to that destination, so a restart resets neither. A refused restart leaves the enrolment under way as it
was. Another destination has its own count and cooldown, so a person who mistyped one can correct it at once, within the
identity's cap.

A factor the combination policy would not accept after the session's first factor is refused as `not_accepted`: always
on a pending session, and on an active one only for the identity's first additional factor while the first factor is
known. Someone signed in by a code to a phone who enrols that same phone would otherwise be short, with nothing to
offer. A later factor is allowed, since it may serve another sign-in.

## The grant

A grant is bound to the identity, the application, the sign-in that started it, the verification generation and what
authorised it, and is single use. Anything that does not match answers `not_found`, so a person learns nothing of a
grant that is not theirs. A bootstrap grant works only on a pending session, and any other only on an active one.

**It lives no longer than what authorised it.** Its expiry is the earlier of `mfa.enrollment.ttl_minutes` and the moment
the step-up or reauthentication stops being fresh, or the pending session expires. The expiry is taken once and never
written again: not by a resend, not by a failed attempt, and not by a later proof. No freshness is judged at
confirmation, because a later step-up must not revive an expired grant. A step-up 800 seconds old against a 900-second
requirement leaves 100 seconds, however long the lifetime is configured.

An expired grant answers `expired`, and its pending factor is discarded. So does one whose verification generation has
moved on, as a reset or a revocation moves it.

## What a confirmation checks again

Inside the confirming transaction, in this order, with the factors as they are stored there:

1. the sign-in is the one the grant was captured for;
2. the grant is bound to the caller, and live;
3. the identity is active, and not locked out;
4. the type is still enabled, and the limits still allow it;
5. what the grant rested on still holds: bootstrap still allows the type, and neither a bootstrap grant nor a
   reauthentication grant has been overtaken by a confirmed factor (`not_fresh`). A step-up grant is unaffected.

The last is why, of two first confirmations racing, exactly one succeeds and counts as first. A later refusal, by the
combination policy or by `PendingCompletion`, rolls back the code's use, the TOTP step, the confirmation, the end of any
re-enrolment obligation and the recovery codes together.

## Codes and attempts

The package computes TOTP codes itself (RFC 6238) and needs no other dependency. A TOTP code is checked within the
window of the grant's application, and its time step is recorded, so the confirming code cannot be used again. A
delivered code goes through the bound `ChallengeGateway` with a purpose of its own, `enrollment`, so it never works as a
sign-in or step-up code, and neither does one of those work here.

Only a wrong or replayed code counts, against the enrolment's own `mfa.enrollment.max_attempts`, default 5. At the cap
the pending factor and its grant are deleted, and `abandoned` is `true` on the result. It keeps the address's throttle
slot. A factor's and an identity's failure counts are not charged. A resend keeps the count; a restart begins a new
enrolment, with a new secret or code and a count of its own. A code that has expired answers `expired` and counts
nothing, so the person may send another.

Starting, resending and confirming are refused as `locked` while the identity's lockout is live. Cancelling is not,
since it only gives something up.

## What a confirmation does

| Session | The proof                                                                                            | What follows                                                                                                                                                                            |
|---------|------------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Pending | Goes to `PendingCompletion`, with purpose `enrollment`, and the whole requirement is evaluated again | `$confirmation->verification` holds the result; the session may stay pending, which is not a failure                                                                                    |
| Active  | Is not recorded, and `StepUp` is not called, because this code was bound to enrolling                | The requirement is evaluated on the proofs the session holds, and the confirmation goes to `SessionTransition` with any shortfall; `$confirmation->completion()` holds what it returned |

So on an `enrolled` application, an active person's first factor returns the session to pending, or with the default
transition lets the middleware gate it, and they verify with the new factor.

With an identity's first additional factor, when recovery codes are enabled and the first factor followed by this one
reaches `recovery_codes.level`, a set is generated and returned once. Otherwise the person generates one later.
Confirming also ends a re-enrolment obligation.

## Delivered codes

A destination is normalised and captured at the start, never resolved from the identity afterwards, so changing the
identity's address cannot redirect codes: E.164 for a phone number (spaces, dashes and parentheses stripped, with no
country assumed) and trimmed lower case for an email address. Anything else is `invalid_destination`. A destination the
identity has already verified still gets a code, as that code is the proof.

A delivery that throws, or a sending cap (`sending_capped`, with `retryAfter`), leaves no factor, grant or event. A code
already sent cannot be recalled: a later failure of the transaction leaves one that nothing can confirm, and nothing
retries the transaction. `resendEnrollmentCode()` goes through the delivered-code cooldown and caps.

A model event that cancels a write the flow needs throws `WriteCanceledException` and rolls the whole change back, so
nothing is reported, issued or left usable for what was not stored.

## Replacing a factor

There is no call for it: enrol the new factor, then remove the old one, each with its own step-up, so the old factor
stays until the new one is confirmed. Leave headroom in the limits for one more, because at a limit the start answers
`limit_reached`. Removing first is not the way, and the last factor policy may refuse it.

## Labels and the preferred factor

Neither changes what a factor proves, so neither needs a step-up; both serve active sessions only. A label is what the
application it was enrolled through shows, so `renameFactor()` answers `not_found` for another application's factor.
`setPreferredFactor()` takes any confirmed factor of a type this application enables. The preference is the identity's
choice, kept on its factors' rows, so it moves away from a factor enrolled through another application too.

## Events

Each waits for the change to commit, so a rollback leaves none.

| Path           | Sequence                                                                                                                                                   |
|----------------|------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Start          | `EnrollmentAbandoned` and `EnrollmentExpired` for what it discards, `EnrollmentStarted`, `CodeSent` when a code was delivered                              |
| Wrong code     | `VerificationFailed` (purpose `enrollment`), and `EnrollmentAbandoned` at the cap                                                                          |
| Expired grant  | `EnrollmentExpired`, `VerificationFailed` (`expired`)                                                                                                      |
| Success        | `VerificationPassed` (purpose `enrollment`), `FactorConfirmed`, `BootstrapEnrollmentCompleted` on the bootstrap path, `RecoveryCodesGenerated` when issued |
| Resend         | `CodeSent`                                                                                                                                                 |
| Cancel         | `EnrollmentAbandoned`                                                                                                                                      |
| Rename, prefer | `FactorRenamed`, `PreferredFactorChanged`                                                                                                                  |

The package sends no notification itself. These carry what you need to tell the person on their existing channels, and
`BootstrapEnrollmentCompleted` is worth telling them about: anyone holding the first factor can take that path.

## Failures

| What happened                                  | Reason                    |
|------------------------------------------------|---------------------------|
| Nobody served, or the sign-in changed          | `not_found`               |
| A grant that is not the caller's, or was used  | `not_found`               |
| Inactive identity                              | `identity_inactive`       |
| Type off, or not listed for bootstrap          | `type_not_enabled`        |
| A passkey, or a combination the policy refuses | `not_accepted`            |
| Destination unusable                           | `invalid_destination`     |
| Identity or address locked                     | `locked`                  |
| No fresh step-up or reauthentication           | `not_fresh`               |
| Bootstrap off                                  | `mfa_enrollment_required` |
| Past a limit                                   | `limit_reached`           |
| Grant or code expired                          | `expired`                 |
| Wrong code                                     | `invalid_code`            |
| Replayed code                                  | `replayed`                |
| Too many codes sent                            | `sending_capped`          |
