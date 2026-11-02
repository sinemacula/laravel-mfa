# Verification

Everything a person proves after their first factor goes through one call: `Mfa::verify()`. It takes a code for a
factor, a code answering a challenge, a recovery code or a passkey's assertion, and answers with one result. Every class
name below is relative to `SineMacula\Laravel\Mfa`.

## The flow

```php
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\Verification\Submission;

$offered = Mfa::offeredFactors();                  // list<FactorSummary>, the preferred first

$sent   = Mfa::sendCode($factorId);                // a SendResult, for an email or SMS factor
$result = Mfa::verify(Submission::challenge($factorId, $sent->challengeId, $code));

$result = Mfa::verify(Submission::factor($factorId, $code));        // TOTP, or a driver of your own
$result = Mfa::verify(Submission::recoveryCode($code));             // a recovery code
$result = Mfa::verify(Submission::assertion($factorId, $response)); // a passkey's response to Mfa::requestAssertion()

if ($result->isFailed()) {
    return response()->json(['reason' => $result->reason->value], 422);
}
```

Only stored factors verify, named by their id, looked up within the identity the request serves: a factor that does not
exist and one that belongs to someone else get the same answer and the same report. The driver is the one registered for
the factor's type.

## Who is served

A request is served as its pending session's identity when the bound `Contracts\PendingSessionResolver` finds one and
its credential allows the action (`mfa.list_factors`, `mfa.send_code`, `mfa.verify`); otherwise as the identity the
guard signed in, when it is a person. A pending session that does not allow the action is served nothing, and the
guard's user is never served in its place. A pending session's first factor must be of the identity's current
verification generation and not dated in the future: one that is not is refused as `not_accepted` before anything is
checked or spent.

## What a code is bound to

The caller, its application, its sign-in and the purpose are captured once, and that one binding runs through the code's
issue, its check and the proof. The sign-in is the pending session's public id or the proof store's current sign-in, and
never the Laravel session's id, so a sign-in that ends on a Laravel session takes its codes with it: a code sent in
sign-in A finds nothing once sign-in B has begun, and is refused as `not_found`, without relying on anything forgetting
it.

With no sign-in there is nothing to bind to, so nothing is sent and nothing is verified. Under the identity's lock the
caller and the binding are resolved again and compared; a difference is refused as `not_found`, counting and reporting
nothing. A bound `PendingSessionResolver` revalidates its credential there, and one that does not validate throws.

### Before the sign-in exists

- **With an authentication layer**, a code binds to the pending session's public id, which survives its activation, so a
  code sent while pending can still answer the same sign-in. A `sign_in` code never answers a `step_up`.
- **Alone**, the default resolver has no pending sessions, and Laravel's `Login` event, or
  `Proofs\GuardHooks::signedIn()`, begins the sign-in before anything resolves a caller. A code before a sign-in cannot
  exist.
- **With your own `PendingSessionResolver` and no authentication layer**, begin the store's sign-in under the pending id
  with `GuardHooks::signedIn()` and a first factor bound to it. The default `PendingCompletion` refuses a proof when the
  store's current sign-in is not the pending id, and never begins one itself. A later `Auth::login()` begins a fresh
  sign-in and forgets the proofs, so use the hooks there too.

A sign-in id must be fresh and never reused, which the `Login` listener's ULID is, and which a caller of `GuardHooks`
must see to. Beginning a sign-in under a pending id grants nothing: the middleware or the pending context still decides.
A guard that fires no event, calls no hook and stays in an existing sign-in stays in that sign-in.

### Overlapping requests

The default `Proofs\SessionProofStore` reads the Laravel session once per request, so the lock cannot show another
request's writes, and the package adds no locking of the session. Serialise overlapping requests on one Laravel session
with `Route::block()` on your verification and sign-in routes. Without it, what still holds is that A's code is refused
in any request that read B, and a proof bound to A cannot be recorded on B. Advancing the verification generation is
what stops proofs counting everywhere (see [Recorded proofs](proofs.md#invalidating-proofs)).

## The purpose

A pending session is always completing its sign-in: any other purpose it asks for is refused as `not_accepted`. An
active session steps up by default, and may ask for `Purpose::SIGN_IN` when a sign-in gated by the `mfa` middleware
completes with no authentication layer. `enrollment` and `reauthenticate` are refused here. All of this happens before
anything is checked or spent. Codes are bound to their purpose, so `sendCode()` and `verify()` must name the same one.

```php
Mfa::sendCode($factorId, Purpose::SIGN_IN);
Mfa::verify(Submission::challenge($factorId, $challengeId, $code), Purpose::SIGN_IN);
```

## Offered factors

`Mfa::offeredFactors()` returns the factors a session can try, as summaries that hold no secret, no code and no full
destination: the identity's confirmed factors, of a type the application enables, that the combination policy accepts
after the session's first factor, the preferred one first, then the oldest, then by id. None are offered while that
first factor is not known, or to an inactive identity, since sending and verifying refuse it as `identity_inactive`.

A factor disabled at the failure ceiling is left out, and so is a passkey while the gateway is unavailable or its
association or credential is missing, because none of those can succeed. A factor under a temporary lockout stays.
Recovery codes are not offered. Offers are advisory: sending and verifying repeat every check.

## Sending a code

`Mfa::sendCode($factorId, $purpose)` asks the bound `Contracts\ChallengeGateway` to send a code for a delivered factor,
and answers with a `Codes\SendResult`: the challenge's id and when the code stops working, or the reason nothing was
sent and, when waiting will help, `retryAfter` in seconds. A send is not an attempt: it resets no count, lifts no
lockout and reports only `CodeSent`. A failing delivery throws `Exceptions\CodeDeliveryFailedException`.

A factor that delivers no codes answers `not_found`. A delivered factor must name its challenge when it is verified:
`Submission::factor()` on one is `not_found`, as is any other kind of submission its factor does not take.

## The result

`Verification\VerificationResult` is told apart by `isVerified()` and `isFailed()`.

| On success     | Holds                                                                                                  |
|----------------|--------------------------------------------------------------------------------------------------------|
| `proof`        | The `Proofs\Proof` made: kind, method, channel, factor, what it observed, time, binding and generation |
| `evaluation`   | The session's proofs with this one against the whole requirement: accepted, multifactor, level, met    |
| `amr`          | The `amr` values of this proof alone, never `mfa`, which only the evaluation can report                |
| `type`         | The type proved: the factor's, or `recovery_code`                                                      |
| `completion()` | Whatever the completion seam returned, such as an authentication layer's tokens                        |

| On failure    | Holds                                                                                                  |
|---------------|--------------------------------------------------------------------------------------------------------|
| `reason`      | The `Enums\FailureReason`, which is what a caller may be told                                          |
| `detail`      | What happened in detail, for logs only                                                                 |
| `lockedUntil` | For `locked` only, when it lifts; none at the failure ceiling, which does not lift by itself           |

A successful verification whose `evaluation` does not yet meet the requirement is still a success: the proof is kept,
and the caller asks for the next factor. A requirement of an operation is not part of `verify()`: ask
`Mfa::isFresh($operation)` afterwards (see [Requirements and step-up](requirements.md)).

A result and a `Submission` never leave through a dump or JSON with anything secret in them. The code, the assertion's
response and the completion are read through `code()`, `response()` and `completion()`, and a channel's destination
through `reference()`: `dump()`, `dd()`, `print_r()`, `var_dump()`, `var_export()` and an array cast show none of them,
`json_encode()` gives what a caller may be told, and `serialize()` throws.

## Failure reasons

| Case                                             | Reason             | `VerificationFailed` | Counted     |
|--------------------------------------------------|--------------------|----------------------|-------------|
| Nobody served, action not allowed, no sign-in    | `not_found`        | none                 | no          |
| The sign-in changed under the lock               | `not_found`        | none                 | no          |
| Factor missing, foreign or removed under the lock| `not_found`        | no factor or type    | no          |
| A submission its factor does not take            | `not_found`        | yes                  | no          |
| Inactive identity                                | `identity_inactive`| yes                  | no          |
| Pending factor                                   | `not_confirmed`    | yes                  | no          |
| Type or recovery codes off                       | `type_not_enabled` | yes                  | no          |
| Not accepted after the first factor              | `not_accepted`     | yes                  | no          |
| A purpose refused, or a recovery code's enrolment| `not_accepted`     | yes                  | no          |
| Lockout or address throttle                      | `locked`           | yes                  | no          |
| Recovery code with no confirmed factor           | `no_factor`        | yes                  | no          |
| Wrong code or assertion                          | `invalid_code`     | yes                  | yes         |
| Expired or spent code, attempts used up          | `expired`          | yes                  | yes         |
| Replayed code, TOTP step or assertion            | `replayed`         | yes                  | yes         |
| Unknown or foreign challenge                     | `not_found`        | yes                  | yes         |
| A seam's refusal                                 | the seam's reason  | yes                  | rolled back |

Confirming an enrolment reports the same way, with its own reasons and its own cap (see [Enrolment](enrollment.md)).

A counted failure also keeps its slot of the address's window; everything else gives it back. A factor or an identity at
the failure ceiling is `locked` with no time: it does not lift by itself. An identity's ceiling blocks recovery codes
while another usable factor can still recover the identity.

## Completion

A success goes to `Contracts\PendingCompletion` on a pending session and `Contracts\StepUp` on an active one, as the
last write of the transaction, after the code is spent and counted. Which seam is decided by pending or active, never by
the purpose.

The defaults, both `Proofs\ProofStoreCompletion`, record the proof in the bound proof store once the transaction
commits. They refuse a binding whose owner, application or session is not the store's current sign-in, and for a pending
session the pending context's as well, as `not_accepted`.

An adapter over an authentication layer binds its own and returns what the caller needs:

```php
final readonly class AuthenticationStepUp implements StepUp
{
    public function stepUp(VerificationResult $result): ?object
    {
        return $this->sessions->stepUp($this->translate($result)); // tokens, opaque to the package
    }
}
```

- A refusal is a thrown `Exceptions\OperationRefusedException` with a reason: it rolls back the count, the code's use,
  the TOTP step and the recovery code's use, and the caller gets a failed result. A still-pending outcome is not a
  refusal: it is a successful completion of this submission. Turning a sibling package's refused result into a throw is
  the adapter's job.
- Any other throwable propagates to the caller, and rolls back too.
- The rollback holds only when the adapter's writes share the storage connection. The lock order is the identity, its
  factors, the challenge, then the authentication layer's session row.
- A store that refuses the proof at the commit throws `Exceptions\ProofRefusedException` from `verify()`, with the code
  spent. It is never turned into an ordinary refusal.

An adapter over authoritative session rows makes `ProofStore::begin()` a no-op for them: activation preserves that row's
sign-in and proofs, and an actual new sign-in uses a new row.

## Counting

Every route counts exactly once, and reports one `VerificationFailed` per attempt: `Attempts\AttemptService` for a code
for a factor, a passkey's assertion and a recovery code, `Attempts\ChallengeCounters::report()` inside the gateway for a
challenge. The address's slot is taken outside any transaction the package opens, and only a counted failure keeps it.
Call `Mfa::verify()` outside a transaction of your own on the storage connection, so the slot and the lock keep that
order (see [Attempts and lockouts](attempts.md)).

## Events

On success, once the transaction commits and in this order: the default seams' proof reaches the store,
`VerificationPassed`, then for a recovery code `RecoveryCodeUsed` and `RecoveryCodesLow`. A listener reading
`Mfa::proofs()` sees the new proof, and a rollback dispatches none of them. A failure's `VerificationFailed` is
dispatched once the transaction has ended. `CodeSent`, `VerificationPassed` and `VerificationFailed` carry the challenge
id when one was used. A passkey's challenge id is the one its gateway reports with a verified assertion, so it is on
`VerificationPassed` and on the `VerificationFailed` of a seam's refusal after it, but not on that of a failed assertion,
which names none.

A listener that throws reaches the caller of `verify()` or `sendCode()`, whatever it throws, and the change has
committed: it is not reported as a failure. See [Events](events.md).
