# Recovery codes

Recovery codes are a fallback for a person who has lost their factors: a set of single-use codes, shown once when the
set is generated, each of which proves the person once in place of a factor. They are not a factor. An identity has one
set, shared by every application, and only an identity with a confirmed factor can have one; each application decides
whether it accepts them, and none does until it says so:

```php
'applications' => [
    'web' => [
        'recovery_codes' => ['enabled' => true],
        // ...
    ],
],
```

The set's size, each code's length and the alphabet it is drawn from are in `recovery_codes` (see
[Recovery codes](configuration.md#recovery-codes) in the configuration guide). What a NIST SP 800-63B-4 claim asks of
them beyond the defaults is in [the compliance profile](compliance.md#recovery-codes).

## Generating a set

`Mfa::generateRecoveryCodes()` generates a new set for the signed-in identity and answers with a
`RecoveryCodes\RecoveryCodeGeneration` holding its codes, once, as `Secrets\RevealedSecret` values. Send them with
`Secrets\SecretResponse::json()`, on a route behind the `mfa.no-store` middleware, so neither the browser nor a proxy
keeps them (see [Secrets](secrets.md)). A route a cookie authenticates needs CSRF protection too (see
[CSRF protection](middleware.md#csrf-protection)):

```php
use Illuminate\Http\Request;
use SineMacula\Laravel\Mfa\Context\CallerContext;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\Secrets\SecretResponse;

Route::post('/mfa/recovery-codes', function (Request $request) {
    $generation = Mfa::generateRecoveryCodes(CallerContext::fromRequest($request));

    if (! $generation->wasGenerated()) {
        return response()->json(['reason' => $generation->reason->value], 403);
    }

    return SecretResponse::json(['recovery_codes' => $generation->codes]);
})->middleware(['auth', 'mfa.no-store']);
```

Each code is 13 characters by default, with no separator; group it for display (`XXXX-XXXX-XXXXX`) as you like, since
spaces and hyphens are ignored when a code is redeemed. The package keeps only a salted hash of each code, so a set it
has returned can never be shown again: a person who lost theirs generates a new one.

A new set replaces the old one in one transaction: the old codes stop working as the new ones start, and a redemption
racing the replacement sees one set or the other, never both and never neither. A refusal answers with its `reason`,
no codes, and `wasGenerated()` false:

| Reason              | When                                                                                    |
|---------------------|-----------------------------------------------------------------------------------------|
| `not_found`         | No signed-in identity that can hold factors, or a pending session: nobody is served     |
| `identity_inactive` | The identity is inactive                                                                |
| `type_not_enabled`  | The application does not accept recovery codes                                          |
| `no_factor`         | The identity has no confirmed factor (a pending one does not count)                     |
| `not_fresh`         | The session has no sign-in, the factor change gate refuses it, or it is below the level |

An `Exceptions\OperationRefusedException` that a seam of your own throws, a freshness gate or a combination policy,
is not one of these: it propagates, leaving the old set. A bound `Contracts\FactorChangeGate`'s refusal is one: refusing
by throwing is how it answers, so its reason is the result's. So does a listener's exception once the set has committed,
which is not a refusal of it.

`RecoveryCodesGenerated` is dispatched once the new set is stored, with its size and generation, never a code.

Generating a set needs a session the bound `Contracts\FactorChangeGate` allows for `mfa.generate_recovery_codes` (by
default, one fresh enough for it) that also reaches the assurance level the application sets for it
(`recovery_codes.level`, `aal2` by default). The level is checked before the codes are drawn and again under the
identity's lock; the gate is asked under the lock only, as one over an authentication layer locks that layer's session
there. A shortfall in either is refused as `not_fresh`, since the remedy is the same stronger step-up. A refusal leaves
the old set intact.

## Redeeming a code

`Mfa::verify($caller, Submission::recoveryCode($code), $purpose)` redeems a code wherever a factor's code is taken: to complete a
pending sign-in or to step up (see [Verification](verification.md)). A code that passes is used up, and its proof is
handed over like a factor's (see [Proofs](proofs.md)): kind `recovery_code`, method `recovery_code`, no channel.

```php
use SineMacula\Laravel\Mfa\Context\CallerContext;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\Verification\Submission;

$result = Mfa::verify(CallerContext::fromRequest($request), Submission::recoveryCode((string) $request->input('code')));

if ($result->isFailed()) {
    return back()->withErrors(['code' => 'That code did not work.']);
}
```

The code is normalised first: case is ignored, and so are spaces, tabs, line breaks and hyphens, so `abcd efgh-jklm`
redeems `ABCDEFGHJKLM`. Nothing else is mapped, and the code is not checked against the configured length or alphabet,
so a set issued before either changed still works.

A redemption is one attempt against the whole unused set: the code is compared with every unused code, without
stopping at a match, so how long it takes says nothing about which code matched or whether one did. It counts against
the identity's and the IP address's attempt limits like a factor's verification, a lockout refuses it before anything
is compared, and a success resets the identity's run of failures (see [Attempts and lockouts](attempts.md)). A
malformed code (longer than any code can be) is compared the same way and fails.

These are refused before any attempt is made, so nothing is counted and no code is spent:

| Reason              | When                                                              |
|---------------------|-------------------------------------------------------------------|
| `identity_inactive` | The identity is inactive                                          |
| `not_accepted`      | The purpose is an enrolment, which a recovery code cannot confirm |
| `type_not_enabled`  | The application does not accept recovery codes                    |
| `no_factor`         | The identity has no confirmed factor                              |
| `not_accepted`      | The session's first factor is not known                           |
| `not_found`         | Nobody is served, or the identity has no sign-in                  |

A code that matches nothing fails with `invalid_code`, and an attempt a lockout refuses with `locked`. An identity at
the failure ceiling is `locked` with no time, while a usable factor can still recover it. Every failure but the last row
above dispatches one `VerificationFailed` with its reason; a success dispatches `VerificationPassed`, then
`RecoveryCodeUsed` with how many codes remain unused, then, when that is at or below `recovery_codes.low_count`,
`RecoveryCodesLow`, so the application can prompt for a new set. Each is dispatched once the change has committed (see
[Events](events.md)). A refusal by the completion seam rolls the code's use back; with the default seams, the proof is
handed to the proof store once the change commits, and a store that refuses it then throws `ProofRefusedException`, with
the code already used.

## Remaining codes

`Mfa::recoveryCodeStatus()` reports where the identity's set stands, without a code:

```php
$status = Mfa::recoveryCodeStatus($caller);

$status?->remaining;    // unused codes of the current set
$status?->generation;   // 0 before the first set
$status?->generatedAt;  // when the current set was generated, or null
$status?->exists();     // whether there is a set, used up or not
```

It is `null` without a signed-in identity that can hold factors.

## When codes go

- **Used.** A used code stays, marked with when it was used, and never redeems again.
- **Replaced.** Generating a new set marks every code of the old one replaced; replaced codes never redeem.
- **With the last factor.** Removing the identity's last confirmed factor (`Mfa::removeFactor()`) removes its set in the
  same transaction and dispatches `RecoveryCodesRemoved`. A pending factor left behind does not keep the set; a
  confirmed one the failure ceiling disabled does.
- **Pruned.** Used and replaced codes are deleted once they are older than `lifecycle.prune_after_days`, by `mfa:prune`
  (see [Pruning](lifecycle.md#pruning)).
- **With a reset.** Resetting the identity removes its set (see [Factor lifecycle](lifecycle.md#resetting-an-identity)).

## Hashing cost

Codes are hashed with your application's Laravel hasher (`config/hashing.php`), bcrypt by default, the same way as
passwords, because codes of 65 bits need a salted, slow hash to resist an offline attack on a stolen table. A
redemption costs one hash check per unused code, so at bcrypt's default cost a full set of 10 takes about as long as
ten password checks; lower `recovery_codes.count`, or the hashing cost, if that is too slow for you. Generating a set
hashes each code once, before the identity's lock is taken.
[Budgets and benchmarks](../design/budgets-and-benchmarks.md) says how this is measured.

Switching hashing driver (from bcrypt to Argon2id, say) with `hashing.*.verify` on, Laravel's default, makes existing
sets fail with the hasher's `RuntimeException` until each identity generates a new one, as it does for passwords.
