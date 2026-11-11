# Testing

Helpers for testing an application that uses the package. Every class name below is relative to
`SineMacula\Laravel\Mfa`.

## Fake delivery

`Testing\FakeSmsSender::fake()` and `Testing\FakeEmailSender::fake()` bind a sender that keeps each `Codes\CodeMessage`
instead of delivering it, and return it. The manager builds a driver on every call, so the next one sends through the
fake.

```php
use SineMacula\Laravel\Mfa\Testing\FakeEmailSender;

$mailbox = FakeEmailSender::fake();

$this->postJson('/mfa/send', ['factor' => $factor->id])->assertOk();

$code = $mailbox->lastCodeTo('person@example.test');
```

| Method                     | What it answers                                         |
|----------------------------|---------------------------------------------------------|
| `sent()`                   | Every message, oldest first                             |
| `sentTo($destination)`     | The messages to the phone number or address             |
| `lastCodeTo($destination)` | The code last sent to the phone number or address       |
| `reset()`                  | Forgets every message so far                            |

Each message also says what the code was for (`purpose`), the application, and the identity it was sent to
(`recipient()`). The fakes keep no wording: to test the wording of an SMS, call `Codes\SmsCodeText::of()` on a message,
and for an email, bind `Codes\MailEmailSender` with `Mail::fake()` and assert on the `MfaCodeMessage` it sent.

An email renders in its captured locale (see [Localisation](localization.md)), so assert on `$message->render()`, not on
`envelope()` called directly in another locale.

## The current TOTP code

`Testing\AuthenticatorApp` stands in for the app a TOTP factor is enrolled in:

```php
use Illuminate\Support\Carbon;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Testing\AuthenticatorApp;

Carbon::setTestNow('2026-11-01 12:00:00');

$factor = Factor::query()->create([
    'authenticatable_type' => $user->getMorphClass(),
    'authenticatable_id'   => (string) $user->getKey(),
    'status'               => 'confirmed',
    ...AuthenticatorApp::FACTOR,
]);

$code = AuthenticatorApp::code($factor);
```

`AuthenticatorApp::code($factor, $steps = 0)` reads the driver's clock, so `Carbon::setTestNow()` is the frozen time,
and works with the factor's own algorithm, digits and period. `$steps` moves it that many periods away.

A code already accepted replays, as a real one does, so for a second verification move the clock or pass `$steps` within
the window.

`AuthenticatorApp::SECRET` is the RFC 6238 SHA-1 key and `AuthenticatorApp::FACTOR` the attributes of a factor enrolled
with it, so a code can be checked against the published vectors. This is public test material, and no enrolment defaults
to it.

A factor that is not `totp`, or whose parameters or secret cannot be read, is refused with an
`InvalidArgumentException`, which never holds the secret.

## Acting as a verified identity

`Testing\Concerns\InteractsWithMfa` acts as an identity with a sign-in the proof store holds, verified at a given time
and level. It needs no particular base test case, so it works with Laravel's and with Testbench's:

```php
use Illuminate\Support\Carbon;
use SineMacula\Laravel\Mfa\Enums\AssuranceLevel;
use SineMacula\Laravel\Mfa\Testing\Concerns\InteractsWithMfa;

final class BillingTest extends TestCase
{
    use InteractsWithMfa;

    public function testClosingTheBooksNeedsARecentVerification(): void
    {
        $this->actingAsVerified($user, at: Carbon::now()->subHour())
            ->postJson('/billing/close')
            ->assertUnauthorized();

        $this->actingAsVerified($user)
            ->postJson('/billing/close')
            ->assertOk();
    }
}
```

| Argument       | Default                                         | What it is                                       |
|----------------|-------------------------------------------------|--------------------------------------------------|
| `$identity`    |                                                 | Who to act as                                    |
| `$level`       | `AssuranceLevel::AAL2`                          | Exactly the level the sign-in must evaluate at   |
| `$at`          | Now                                             | When the proofs were made; the future is refused |
| `$guard`       | The default guard                               | The guard to act on, which becomes the default   |
| `$application` | The request's resolved one, or the guard's name | Where the proofs go                              |

It records a password first factor and one further proof at the same time, then reads them back the way the route gate
does, against additional verification and the level:

| Level  | The further proof                                                                                 | Under the default policy                    |
|--------|---------------------------------------------------------------------------------------------------|---------------------------------------------|
| `AAL1` | An email code to a synthetic address: accepted, not multifactor                                   | Meets additional verification, and not AAL2 |
| `AAL2` | TOTP: multifactor                                                                                 | Meets AAL2                                  |
| `AAL3` | A passkey observing presence, user verification, phishing resistance and a hardware-protected key | Fails: the default policy caps at AAL2      |

It throws a `LogicException` unless the sign-in reaches exactly that level, so a test asking for AAL1 cannot pass a
route it meant to fail. The message names all three facts:

```text
Requested aal3 with additional verification; reached aal2; unmet: minimum_level.
```

To use `AAL3`, bind a combination policy that rates such evidence AAL3. `AssuranceLevel::UNCLASSIFIED` and a future time
are refused with an `InvalidArgumentException` before anything changes.

The table and the check are public in `Testing\LevelEvidence`, for a helper of your own: `furtherProof()` builds a
level's further proof, naming the factor you give or the synthetic one; `evaluate()` reads a sign-in as the route gate
does; and `assertReached()` throws the `LogicException` above.

### What it does not do

- It is a fixture for gating routes, not a statement that your sign-in can reach that level.
- It dispatches no `Login` and no MFA event. Laravel's `Authenticated` still fires from `setUser()`.
- It enrols no factor through the default recorder, so `isMfaEnabled()` does not change, and it bypasses no inactivity
  check, re-enrolment obligation or stricter requirement. The route's whole requirement is not checked, since your
  application may ask more than the fixture arranges.
- It needs the package's migrations, to read the identity's verification generation.
- The application it is given chooses where the proofs go, not what the next request resolves. Have the two agree.

### Stores, guards and sessions

- The sign-in is begun and its proofs recorded through `Testing\Contracts\VerifiedSignInRecorder`, by default the bound
  proof store itself. A store that refuses proofs it did not make, such as one backed by an authentication layer's
  sessions, binds a recorder that begins the sign-in and records the evidence through that layer. `begin()` is handed
  the time the proofs are made at and returns the sign-in's session id. The helper then records a password first factor,
  unless the store already holds one, and exactly one further proof, an additional factor bound for sign-in, both at
  that time. `record()` keeps each proof's time, method, kind of channel and observed properties, or throws. A layer
  that holds a sign-in pending until it is verified may complete it with the further proof, but the sign-in begun must
  be the store's current one once the proofs are recorded, and never another. The proofs are still read back through the
  store, so what the recorder writes must count there: a store counting a proof only while the identity holds its factor
  needs that factor arranged too. The recorder's `factorReference()` names the factor the further proof is made with,
  by default a synthetic one; return the id of a factor you enrolled where the store refuses a proof of any other.
- A store whose `begin()` does nothing needs its session arranged first, otherwise a `LogicException` says so. If it
  retains a first factor, that first factor is kept, and one later than `$at` fails, since the further proof would not
  count. If it retains anything further, a `LogicException` says the time cannot be honoured.
- A first factor from a bound `FirstFactorResolver` is not preserved: the store's password proof stands in for it, so a
  declared `email` or `sms` first factor does not stop a recipe reaching AAL2.
- A guard already holding this identity, by its class and its auth identifier, is not given it again, so a guard with
  its own context can be arranged by its own helper first.
- The default store writes to the Laravel session. A test that also carries a session cookie with its own `mfa.proofs`
  gets those instead, because a stored value wins when the session starts. An ordinary fresh test session works.

## Proving a seam

`Testing\Seams` holds a contract test kit for each seam an adapter implements. See
[Extending](extending.md#proving-an-adapter).
