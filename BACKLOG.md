# Backlog

Forward-looking work that still needs to land in `sinemacula/laravel-mfa` before the 1.0 release.

Phases 1–5 (foundations → manager orchestration → drivers → middleware polish → hygiene) and Phase 9 (full test
suite) are complete and not tracked here. The git log carries the audit trail. This file is scoped to the work
that remains.

---

## Status

- **100% line / method / class coverage** on `src/` (498/498 lines, 134/134 methods, 26/26 classes)
- **303 tests passing** across Unit / Feature / Integration / Performance suites
- **Mutation testing gate green** — 92% Covered MSI on scoped paths (gate: 90%)
- **PHPBench benchmarks** covering every hot-path (TOTP, OTP, backup codes, FactorSummary)
- **`composer check` clean** on `src/` and `benchmarks/` (only pre-existing markdown lint on the PRD and
  informational radarlint code-smell warnings remain)

**Release-blocking work that still needs to land before 1.0:**

- **B-18** — TOTP provisioning URI helper (enrolment DX for the most-used driver)
- **B-19** — Configurable code alphabet (PRD P1)
- **B-20** — Step-up middleware variant (PRD primary persona)
- **B-22** — Rate-limit recipe in README (defence-in-depth documentation)

Detailed implementation specs for each are under "Phase 6 — Release blockers" and "Phase 7 — Release docs"
below. Every item must land before tagging 1.0.

---

## Architecture reference

The package is designed to operate cleanly in three modes. Any new work must keep all three working.

### Standalone

- Identity model implements `MultiFactorAuthenticatable`.
- Default `SessionMfaVerificationStore` keeps verification state in the session (per-device by construction).
- Works behind SessionGuard, Sanctum, Passport, or any custom guard whose `Auth::user()` returns a
  `MultiFactorAuthenticatable`.

### Paired with `sinemacula/laravel-authentication`

- The same identity model implements both `Identity` (from the auth package) and `MultiFactorAuthenticatable`
  (from this package). Both contracts extend Laravel's standard `Authenticatable`, so a single class satisfies
  both.
- Verification state should live on the `Device` record (`last_mfa_verified_at`) because the auth package is
  stateless. The seam is the `MfaVerificationStore` contract — paired-mode apps rebind it. This package must
  **never** import anything from `SineMacula\Laravel\Authentication\*`; the bridge is constructed in the
  consumer's service provider or in the `laravel-iam` glue.

### Wrapped by `sinemacula/laravel-iam`

- Parent package provides: a `DeviceMfaVerificationStore` binding (B-23, out of repo), an opinionated
  `OrganisationMfaPolicy` bound against the `MfaPolicy` contract, cross-package event listeners (audit log),
  and any other opinionated defaults.
- This repo stays clean of parent-package knowledge. The extension seams (policy, store, gateway) must be
  expressive enough that the parent package does not need to monkey-patch.

---

## Resolved decisions

Historical record of the architectural calls made during Phases 1–5. Anything new should be consistent with
these unless explicitly discussed.

- **D1 — Generic `MfaPolicy` contract, not org-specific `EnforcesMfa`.** The package ships a `MfaPolicy`
  extension seam with a no-op default (`NullMfaPolicy`). Consumers bind their own policy (org-aware,
  role-aware, feature-flag-aware). `laravel-iam` ships an opinionated `OrganisationMfaPolicy` at its layer.
  The MFA package never learns the word "organisation".
- **D2 — Single `mfa_factors` table.** Columns include `attempts`, `locked_until`, `last_attempted_at`,
  `verified_at`. No separate `mfa_attempts` log — audit goes through events, owned by `laravel-audit-log`.
- **D3 — Challenge split between manager and driver.** `MfaManager::challenge()` orchestrates (events, future
  rate-limiting, logging). `FactorDriver::issueChallenge(Factor): void` implements per-factor-type transport
  (no-op for TOTP, mail dispatch for email, gateway dispatch for SMS, no-op for backup codes since they are
  pre-issued).
- **D4 — Per-device verification is the default.** In paired mode the verification timestamp lives on the
  `Device` record; in standalone mode it lives on the session (which is already per-device). Step-up
  middleware (B-20) is the escape hatch for "re-verify before this specific action regardless of device
  state".

---

## Phase 6 — Release blockers

All three items must land before 1.0. They are independent of each other and can be shipped as three separate
PRs.

### B-18 — TOTP provisioning URI helper

**Why:** TOTP is the highest-traffic driver. Every enrolment UI needs the `otpauth://` URI so it can render a
QR code (via the consumer's QR-rendering library of choice). Without this helper every consumer either fishes
`pragmarx/google2fa` out of the container directly (leaks a transitive dep into their app code) or hand-builds
the URI from spec (error-prone, repeated work).

**Files to touch:**

- `src/Drivers/TotpDriver.php` — add `provisioningUri()` method
- `tests/Unit/Drivers/TotpDriverTest.php` — add coverage
- `README.md` — add an "Enrolment" subsection under "Usage" showing the helper in action

**Method to add:**

```php
public function provisioningUri(
    string $issuer,
    string $accountName,
    #[\SensitiveParameter] string $secret,
): string
```

**Behaviour:**

- Wraps `Google2FA::getQRCodeUrl($issuer, $accountName, $secret)`. The Google2FA library URL-encodes the
  issuer and account name internally; do NOT double-encode.
- Returns the canonical `otpauth://totp/{issuer}:{accountName}?secret={base32}&issuer={issuer}` form.
- `#[\SensitiveParameter]` attribute on `$secret` so it does not leak into stack traces.

**Test cases (new in `TotpDriverTest`):**

- Returns a string starting with `otpauth://totp/`.
- Issuer + account name appear in the URI.
- Secret appears as the `secret` query parameter (base32, unaltered).
- `issuer` query parameter is also present (the standard auth-app behaviour).
- Reflection check: the `$secret` parameter carries `#[\SensitiveParameter]`.

**README addition (under a new "Enrolment" subsection in "Usage"):**

```php
$driver = Mfa::driver('totp');
$secret = $driver->generateSecret();
$uri    = $driver->provisioningUri(
    issuer: config('app.name'),
    accountName: $user->email,
    secret: $secret,
);

// Render $uri as a QR code with your library of choice. With endroid/qr-code:
//   $qr = Builder::create()->writer(new PngWriter)->data($uri)->build();
//
// Then persist the secret on a Factor row:
Factor::create([
    'authenticatable_type' => $user::class,
    'authenticatable_id'   => $user->getKey(),
    'driver'               => 'totp',
    'label'                => 'Authenticator app',
    'secret'               => $secret,
]);
```

**Exit criteria:** new method covered (line + branch); `composer check` clean; `composer test` green; coverage
remains 100% on `src/`.

---

### B-19 — Configurable code alphabet (email / SMS)

**Why:** Some consumers want non-numeric OTP codes (e.g. unambiguous Crockford-base32, alphabetic codes for
voice-call delivery, or extended numeric for higher-entropy SMS). PRD P1 explicitly. The plumbing already
exists for `BackupCodeDriver`; mirror it on the OTP path.

**Files to touch:**

- `src/Drivers/AbstractOtpDriver.php` — accept `?string $alphabet` constructor arg (default `null`); thread
  it into `generateCode()`
- `src/Drivers/EmailDriver.php` — pass the alphabet through to the parent constructor
- `src/Drivers/SmsDriver.php` — same
- `src/MfaManager.php` — `createEmailDriver()` / `createSmsDriver()` read `alphabet` from driver config and
  pass it through
- `config/mfa.php` — add an `alphabet` key under `drivers.email` and `drivers.sms` (default `null`)
- `tests/Unit/Drivers/AbstractOtpDriverTest.php`, `EmailDriverTest.php`, `SmsDriverTest.php`,
  `DefaultsTest.php` — coverage

**Constructor surface (`AbstractOtpDriver`):**

```php
public function __construct(
    protected readonly int $codeLength = 6,
    protected readonly int $expiry = 10,
    protected readonly int $maxAttempts = 3,
    protected readonly ?string $alphabet = null,
) {}
```

**Behaviour:**

- `null` alphabet = current numeric behaviour (backwards compatible — every existing test must keep passing).
- Empty string alphabet = throw `InvalidArgumentException` from the constructor (fail-fast at construction
  rather than at first `generateCode()` call).
- Single-character alphabet = throw `InvalidArgumentException` (entropy is zero; almost certainly a bug).
- Otherwise: `generateCode()` picks `$codeLength` characters from the alphabet uniformly via `random_int`.
- Must use `random_int` (not `mt_rand`); it is the only PHP RNG that is cryptographically suitable.
- Add a `getAlphabet(): ?string` getter on `AbstractOtpDriver` for symmetry with the existing getters.

**Manager wiring (`MfaManager::createEmailDriver()`):**

```php
return new EmailDriver(
    mailer: $this->container->make(Mailer::class),
    mailable: $config['mailable']        ?? MfaCodeMessage::class,
    codeLength: $config['code_length']   ?? 6,
    expiry: $config['expiry']            ?? 10,
    maxAttempts: $config['max_attempts'] ?? 3,
    alphabet: $config['alphabet']        ?? null,
);
```

(Same shape for `createSmsDriver()`.)

**Config additions (`config/mfa.php`):**

```php
'email' => [
    'code_length'  => (int) env('MFA_EMAIL_CODE_LENGTH', 6),
    'expiry'       => (int) env('MFA_EMAIL_EXPIRY_MINUTES', 10),
    'max_attempts' => (int) env('MFA_EMAIL_MAX_ATTEMPTS', 3),
    'alphabet'     => env('MFA_EMAIL_ALPHABET'),
],

'sms' => [
    'code_length'      => (int) env('MFA_SMS_CODE_LENGTH', 6),
    'expiry'           => (int) env('MFA_SMS_EXPIRY_MINUTES', 10),
    'max_attempts'     => (int) env('MFA_SMS_MAX_ATTEMPTS', 3),
    'alphabet'         => env('MFA_SMS_ALPHABET'),
    'message_template' => env('MFA_SMS_MESSAGE_TEMPLATE', 'Your verification code is: :code'),
],
```

**Test cases:**

- `null` alphabet → `generateCode()` returns a string of digits-only (regression: existing tests still pass).
- Custom alphabet `'AB'` → every char of every generated code is in `['A', 'B']`.
- Custom alphabet `'0123456789ABCDEF'` (hex) → every char is hex.
- Empty alphabet → constructor throws.
- Single-char alphabet → constructor throws.
- `getAlphabet()` returns the configured value (including null).
- `DefaultsTest` updated to assert `getAlphabet() === null` for the unconfigured email / SMS drivers.
- A driver-config test that proves the manager passes `alphabet` through from
  `config('mfa.drivers.email.alphabet')`.

**Exit criteria:** all existing tests still green; new branches covered; `composer check` clean.

---

### B-20 — Step-up middleware via parameterised `RequireMfa`

**Why:** PRD primary persona "step-up authentication implementer" needs to demand a *recent* verification on
specific routes (delete account, view PII, financial transactions) without forcing the global `default_expiry`
to be aggressive. Without this lever the only choice is "global short expiry = annoying" or "global long
expiry = insecure for sensitive actions".

**Decision: parameterise the existing `RequireMfa` middleware rather than ship a second one.** Reasons:

- One middleware to remember (`mfa` and `mfa:5` both come from the same alias).
- Matches Laravel's built-in idiom (`auth:guard`, `throttle:60,1`, `can:update,post`).
- Backwards compatible: `mfa` (no param) keeps current semantics.
- `MfaManager::hasExpired()` already takes an optional `int $expiresAfter` argument — wiring is trivial.

**Files to touch:**

- `src/Middleware/RequireMfa.php` — accept `?string $maxAgeMinutes` as a third `handle()` argument
- `tests/Feature/RequireMfaMiddlewareTest.php` — new tests for step-up
- `README.md` — short "Step-up authentication" subsection under the middleware docs

**Method signature:**

```php
public function handle(
    Request $request,
    \Closure $next,
    ?string $maxAgeMinutes = null,
): Response
```

(Laravel passes route middleware params as strings — cast to int and validate.)

**Behaviour:**

- No third argument: pass `null` to `Mfa::hasExpired()` (current behaviour, uses `default_expiry`).
- Numeric string argument: cast to int, validate `>= 0`, pass to `Mfa::hasExpired((int) $maxAgeMinutes)`.
- Non-numeric argument: throw `InvalidArgumentException` (programmer error — fail at boot, not at request).
- Verification age strictly greater than `maxAgeMinutes` → `MfaExpiredException`.
- `mfa:0` → strict every-request (every prior verification treated as expired; consistent with the
  `default_expiry = 0` semantics on `MfaManager::hasExpired`).

**Routes example for the README:**

```php
// Standard MFA gate (uses default_expiry from config)
Route::middleware('mfa')->group(function () {
    Route::get('/dashboard', DashboardController::class);
});

// Step-up gate: require verification within the last 5 minutes
Route::middleware('mfa:5')->delete('/account', AccountController::class);

// Strict every-request gate for the highest-risk actions
Route::middleware('mfa:0')->post('/api/admin/delete-everything', NukeController::class);
```

**Test cases (new in `RequireMfaMiddlewareTest`):**

- `mfa:5` with a 4-minute-old verification → request passes through (no exception).
- `mfa:5` with a 6-minute-old verification → throws `MfaExpiredException`.
- `mfa:0` with any prior verification → throws `MfaExpiredException`.
- `mfa:60` overrides a `default_expiry` shorter than 60 minutes (proves the route param wins over config).
- Non-numeric param (e.g. `mfa:abc`) → `InvalidArgumentException` at middleware construction / handling.
- Negative param (e.g. `mfa:-1`) → `InvalidArgumentException`.
- Existing `mfa` (no param) tests continue to pass unchanged.

**Exit criteria:** existing tests still green; new branches covered; coverage stays 100%; `composer check`
clean.

---

## Phase 7 — Release docs

### B-22 — Rate-limit recipe in README

**Why:** `MfaManager` lockouts protect a single factor row from runaway attempts on the same code, but they do
not protect against:

- Distributed brute-force across many factors (e.g. attacker with a leaked email list trying common codes).
- User-enumeration attacks via differential timing on the verify endpoint.
- DoS via flooding the verify endpoint to fill the lockout window for legitimate users.

The right fix is HTTP-layer rate limiting (per-IP and per-identity) using Laravel's built-in `RateLimiter`.
Consumers can wire this in 30 lines of config — but they need to know to do it. Document the recipe.

**Files to touch:**

- `README.md` — new "Rate limiting" subsection under "Security model" (or under "Middleware" if no security
  section exists yet)

**Content outline:**

1. Two-line "what + why": package handles per-factor lockouts; consumers must add per-IP / per-identity
   rate limiting at the HTTP layer for defence-in-depth.
2. Worked example using Laravel's `RateLimiter` facade in a service provider.
3. Wiring example showing the rate-limit middleware on the verification endpoint.
4. One-line note that the limiter must NOT be applied to routes that simply READ MFA state (e.g.
   `Mfa::shouldUse()` checks); only to the verify endpoint itself.

**Worked example:**

```php
// app/Providers/AppServiceProvider.php (boot method)
use Illuminate\Cache\RateLimiting\Limit;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\RateLimiter;

RateLimiter::for('mfa-verify', static function (Request $request): array {
    $identifier = optional($request->user())->getAuthIdentifier()
        ?? $request->ip();

    return [
        // Per-IP cap for unauthenticated / spray attacks
        Limit::perMinute(10)->by($request->ip() ?? 'unknown'),

        // Per-identity cap so one compromised IP can't brute many users
        Limit::perMinute(5)->by((string) $identifier),
    ];
});
```

```php
// routes/web.php
Route::post('/mfa/verify', VerifyController::class)
    ->middleware(['mfa.skip', 'throttle:mfa-verify']);
```

**Optional second example:** a per-driver throttle (separate buckets for `email` / `sms` / `totp`) for apps
that want different sensitivity levels per factor type. Skip if the README is getting long.

**Exit criteria:** README renders correctly via the markdown lint plugin (the existing markdown lint warnings
in `docs/prd/02-laravel-mfa.md` are pre-existing and out of scope; do NOT edit the PRD as part of this).

---

## Phase 8 — Out of scope (delivered by `sinemacula/laravel-iam`)

Not this repo's work, tracked here for visibility so the IAM glue's authors know what to wire.

### B-23 — `DeviceMfaVerificationStore`

A `MfaVerificationStore` implementation that reads / writes the `last_mfa_verified_at` column on the `Device`
record from `sinemacula/laravel-authentication`. This is what makes paired-mode (stateless JWT, Sanctum
personal access tokens, Passport) verification persist *per device* instead of leaning on the session —
without it the default `SessionMfaVerificationStore` cannot work for stateless stacks.

Lives in `laravel-iam` because that package is the only one allowed to depend on both `laravel-mfa` and
`laravel-authentication`. The shape of the integration:

```php
// In laravel-iam's service provider:
$this->app->singleton(MfaVerificationStore::class, DeviceMfaVerificationStore::class);
```

```php
// laravel-iam/src/Stores/DeviceMfaVerificationStore.php
final readonly class DeviceMfaVerificationStore implements MfaVerificationStore
{
    public function __construct(private AuthManager $auth) {}

    public function markVerified(Authenticatable $identity, ?CarbonInterface $at = null): void
    {
        $device = $this->auth->guard()->device(); // contextual accessor on the auth package
        if ($device instanceof EloquentDevice) {
            $device->forceFill(['last_mfa_verified_at' => $at ?? now()])->save();
        }
    }

    public function lastVerifiedAt(Authenticatable $identity): ?CarbonInterface
    {
        return $this->auth->guard()->device()?->getLastMfaVerification();
    }

    public function forget(Authenticatable $identity): void
    {
        $device = $this->auth->guard()->device();
        if ($device instanceof EloquentDevice) {
            $device->forceFill(['last_mfa_verified_at' => null])->save();
        }
    }
}
```

The MFA package's `MfaVerificationStore::markVerified()` accepts an optional `CarbonInterface $at` precisely
so this implementation can stamp the device row atomically with the verification event.
