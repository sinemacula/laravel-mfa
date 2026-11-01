# Recovery Codes

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
[Recovery codes](configuration.md#recovery-codes) in the configuration guide).

## Generating a set

`Mfa::generateRecoveryCodes()` generates a new set for the signed-in identity and returns its codes, once, as
`Secrets\RevealedSecret` values. Send them with `Secrets\SecretResponse::json()`, on a route behind the `mfa.no-store`
middleware, so neither the browser nor a proxy keeps them (see [Secrets](secrets.md)):

```php
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\Secrets\SecretResponse;

Route::post('/mfa/recovery-codes', function () {
    return SecretResponse::json(['recovery_codes' => Mfa::generateRecoveryCodes()]);
})->middleware(['auth', 'mfa.no-store']);
```

Each code is 12 characters by default, with no separator; group it for display (`XXXX-XXXX-XXXX`) as you like, since
spaces and hyphens are ignored when a code is redeemed. The package keeps only a salted hash of each code, so a set it
has returned can never be shown again: a person who lost theirs generates a new one.

A new set replaces the old one in one transaction: the old codes stop working as the new ones start, and a redemption
racing the replacement sees one set or the other, never both and never neither. Generation is refused with an
`Exceptions\OperationRefusedException` carrying its reason:

| Reason              | When                                                                |
|---------------------|---------------------------------------------------------------------|
| `machine_identity`  | The identity is not a person                                        |
| `identity_inactive` | The identity is inactive                                            |
| `type_not_enabled`  | The application does not accept recovery codes                      |
| `no_factor`         | The identity has no confirmed factor (a pending one does not count) |

`RecoveryCodesGenerated` is dispatched once the new set is stored, with its size and generation, never a code. Without
a signed-in identity that can hold factors, `generateRecoveryCodes()` returns an empty list.

Generating a set will need a fresh step-up and a session at the assurance level the application sets for it
(`recovery_codes.level`); neither is applied yet, so put your own step-up in front of the route until it is.

## Redeeming a code

`Mfa::redeemRecoveryCode($code, $purpose)` redeems a code for the signed-in identity, for a sign-in (the default), a
step-up or a reauthentication, and returns whether it passed. A code that passes is used up, and its proof is recorded
on the identity's current sign-in like a factor's (see [Proofs](proofs.md)): kind `recovery_code`, method
`recovery_code`, no channel.

```php
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Facades\Mfa;

if (!Mfa::redeemRecoveryCode((string) $request->input('code'), Purpose::STEP_UP)) {
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
| `machine_identity`  | The identity is not a person                                      |
| `identity_inactive` | The identity is inactive                                          |
| `not_accepted`      | The purpose is an enrolment, which a recovery code cannot confirm |
| `type_not_enabled`  | The application does not accept recovery codes                    |
| `no_factor`         | The identity has no confirmed factor                              |
| `not_accepted`      | The identity has no sign-in to record the proof on                |

A code that matches nothing fails with `invalid_code`, and an attempt a lockout refuses with `locked`. Every failure
dispatches one `VerificationFailed` with its reason and the type `recovery_code`; a success dispatches
`VerificationPassed`, then `RecoveryCodeUsed` with how many codes remain unused, then, when that is at or below
`recovery_codes.low_count`, `RecoveryCodesLow`, so the application can prompt for a new set. Each is dispatched once
the change has committed (see [Events](events.md)). The code is used up and the proof handed to the proof store once
the change commits; a store that refuses the proof throws `ProofRefusedException`, with the code already used. A
sign-in that ends while the code is being checked also throws `ProofRefusedException`, but then the code is left unused
and nothing is counted: a redemption never passes without its proof.

The unified verification, which will take a recovery code wherever it takes a factor's code and answer with a
structured result, is not shipped yet; until it is, call `redeemRecoveryCode()` from your own route where you would
verify a factor.

## Remaining codes

`Mfa::recoveryCodes()` reports where the identity's set stands, without a code:

```php
$status = Mfa::recoveryCodes();

$status?->remaining;    // unused codes of the current set
$status?->generation;   // 0 before the first set
$status?->generatedAt;  // when the current set was generated, or null
$status?->exists();     // whether there is a set, used up or not
```

It is `null` without a signed-in identity that can hold factors.

## When codes go

- **Used.** A used code stays, marked with when it was used, and never redeems again.
- **Replaced.** Generating a new set marks every code of the old one replaced; replaced codes never redeem.
- **With the last factor.** Removing the identity's last confirmed factor (`Mfa::disable()`) removes its set in the
  same transaction and dispatches `RecoveryCodesRemoved`. A pending factor left behind does not keep the set; a
  confirmed one the failure ceiling disabled does.
- **Pruned.** Used and replaced codes are deleted once they are older than `lifecycle.prune_after_days`; the pruning
  command is not shipped yet.

## Hashing cost

Codes are hashed with your application's Laravel hasher (`config/hashing.php`), bcrypt by default, the same way as
passwords, because codes of 60 bits need a salted, slow hash to resist an offline attack on a stolen table. A
redemption costs one hash check per unused code, so at bcrypt's default cost a full set of 10 takes about as long as
ten password checks; lower `recovery_codes.count`, or the hashing cost, if that is too slow for you. Generating a set
hashes each code once, before the identity's lock is taken.

Switching hashing driver (from bcrypt to Argon2id, say) with `hashing.*.verify` on, Laravel's default, makes existing
sets fail with the hasher's `RuntimeException` until each identity generates a new one, as it does for passwords.
