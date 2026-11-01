# Recorded proofs

Every verification made on a signed-in session is recorded as a proof (see
[Proofs, assurance and requirements](assurance.md#proofs)) on that session's sign-in, and everything the package later
decides about the session is read back from those records, never from a single "verified at" time. Every class name
below is relative to `SineMacula\Laravel\Mfa`.

## Reading the proofs

`Mfa::proofs()` returns the proofs of the current identity's sign-in on the current application that still count,
oldest first:

```php
use SineMacula\Laravel\Mfa\Enums\ProofKind;
use SineMacula\Laravel\Mfa\Facades\Mfa;

foreach (Mfa::proofs() as $proof) {
    $proof->kind;        // ProofKind::ADDITIONAL_FACTOR, ProofKind::RECOVERY_CODE, ...
    $proof->method;      // 'totp', 'email', 'sms', 'backup_code', ...
    $proof->reference;   // the factor it was made with
    $proof->provedAt;    // CarbonImmutable
}
```

The current application is the one a bound `Contracts\ApplicationResolver` names for the request, or the default
guard's name without one. The list is empty without an MFA-capable identity or a sign-in.

A recorded proof stops counting, and is left out, when:

- it is bound to another identity, application or sign-in;
- it was made after now;
- it was made under another verification generation than the identity's current one (see
  [Invalidating proofs](#invalidating-proofs));
- the factor it was made with has been disabled on this session;
- it cannot be read back.

A successful `Mfa::verify()` records an additional factor proof of the factor on the driver's channel, or a recovery
code proof for a backup code. A driver whose channel cannot carry a factor (`ChannelKind::carriesFactor()`) proves
nothing.

## Sign-ins

A sign-in is the run of a session between signing in and signing out, named by the session id its proofs are bound to.
With a guard that fires Laravel's `Login` and `Logout` events, such as the session guard, nothing needs doing: `Login`
begins a new sign-in for the identity and `Logout` forgets it. Beginning a sign-in forgets everything the identity's
previous one proved, so another identity on a reused session, or the same identity signing in again, inherits nothing.

A guard that sets the user without firing `Login` leaves no sign-in, so a verification still succeeds but records
nothing, and the `mfa` middleware keeps requiring one. That includes Laravel's `actingAs()` in tests: sign the user in
with `Auth::login()` when a test needs proofs recorded.

## Custom guards

A guard that fires neither event calls the hooks in `Proofs\GuardHooks` instead: `signedIn()` once it has signed the
identity in, with the proof of the first factor it used, and `signedOut()` once it has signed them out.

```php
use Carbon\CarbonImmutable;
use SineMacula\Laravel\Mfa\Assurance\Channel;
use SineMacula\Laravel\Mfa\Assurance\ObservedProperties;
use SineMacula\Laravel\Mfa\Enums\ChannelKind;
use SineMacula\Laravel\Mfa\Enums\ProofKind;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Proofs\GuardHooks;
use SineMacula\Laravel\Mfa\Proofs\Proof;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
use SineMacula\Laravel\Mfa\Proofs\VerificationGeneration;

GuardHooks::signedIn($user, new Proof(
    kind: ProofKind::FIRST_FACTOR,
    method: 'password',
    channel: new Channel(ChannelKind::PASSWORD),
    reference: null,
    properties: ObservedProperties::none(),
    provedAt: CarbonImmutable::now(),
    binding: new ProofBinding($user->getMorphClass(), (string) $user->getKey(), 'web', $signInId, Purpose::SIGN_IN),
    generation: VerificationGeneration::current($user),
));

GuardHooks::signedOut($user);
```

The proof must be a first factor bound to the identity and made under its current verification generation; anything
else is refused with an `InvalidArgumentException`, as it would never count. Its session id names the sign-in, and the
proofs that follow are bound to it. A guard that calls neither hook leaves no proof to rely on.

## Stateless guards

The default store, `Proofs\SessionProofStore`, keeps each identity's sign-in and its proofs in the Laravel session under
`mfa.proofs`, at most 50 proofs per sign-in (the earliest recorded is forgotten first, never the first factor). A guard
with no session (tokens, JWTs) binds its own `Contracts\ProofStore`, keyed by an id that names one sign-in, not merely a
device:

| Method                               | Does                                                                              |
|--------------------------------------|-----------------------------------------------------------------------------------|
| `begin($identity, $sessionId)`       | Begins a sign-in named by the session id, forgetting the previous one's proofs    |
| `currentSession($identity)`          | The current sign-in's session id, or `null` without one                           |
| `record($proof)`                     | Keeps a proof bound to its identity's current sign-in, refusing any other         |
| `proofs($identity, $application)`    | The current sign-in's proofs on the application that still count, oldest first    |
| `forgetFactor($identity, $factorId)` | Stops counting the proofs made with the factor                                   |
| `forget($identity)`                  | Forgets the current sign-in and its proofs                                       |

A store refuses a proof it cannot keep by throwing `Exceptions\ProofRefusedException`, and fails closed when it reads:
no record, a proof in the future, another generation, identity, application or sign-in all mean not verified.

```php
use SineMacula\Laravel\Mfa\Contracts\ProofStore;

$this->app->bind(ProofStore::class, TokenProofStore::class);
```

## Invalidating proofs

Disabling a factor (`Mfa::disable()`) stops every proof made with it counting on the current session. The session store
cannot reach the identity's other sessions; to make them verify again, advance the identity's verification generation:

```php
use SineMacula\Laravel\Mfa\Proofs\VerificationGeneration;

VerificationGeneration::advance($user);
```

The generation is a durable counter on the identity's row in the identity states table, stamped on every proof. Once
it moves on, every proof recorded under an earlier generation stops counting, on every session, at its next read.
Called inside the identity's factor state transaction, the advance commits or rolls back with the change it belongs to.

## The middleware

The `mfa` middleware judges the newest additional factor or recovery code proof of the current sign-in: with none it
throws `MfaRequiredException`, and with one older than the window (the route's `mfa:N` minutes, or
`proofs.max_age_minutes`, see [Proofs](configuration.md#proofs)), or dated in the future, `MfaExpiredException`. A first
factor alone is never a verification.

How the store is built, and why each rule holds, is in [the proof store design note](../design/proof-store.md).
