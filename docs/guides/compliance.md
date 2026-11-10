# NIST SP 800-63B-4 compliance profile

This profile says what the package classifies and what an application must also configure to claim an authenticator
assurance level from [NIST SP 800-63B-4](https://pages.nist.gov/800-63-4/sp800-63b.html). Section numbers below are that
publication's. Every class name is relative to `SineMacula\Laravel\Mfa`.

The package reports the level a session's proofs support, from what those proofs observed (see
[Classification](assurance.md#classification)). That level describes the authenticators only. Whether a deployment
meets a level also depends on its session lifetimes, its reauthentication, its risk assessment and much else that no
library can see. This is not a certification, and nothing here makes the package, or an application using it, compliant
by itself. It is guidance for your own assessment, which remains yours.

## The checklist

| To claim            | Do this                                                                                  | See                                                                               |
|---------------------|------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------|
| Any level           | Declare a known first factor, and ask for a level rather than an additional verification | [Unclassified evidence](#unclassified-evidence), [Factor types](#factor-types)    |
| Any level, with SMS | Offer an alternative, tell people the risk, assess it and plan to migrate                | [Restricted SMS](#restricted-sms)                                                 |
| AAL2                | Enable TOTP or a passkey, and offer a phishing-resistant option through a bound gateway  | [Factor types](#factor-types), [Phishing resistance](#phishing-resistance)        |
| AAL3                | Bind a combination policy of your own, with evidence of hardware-protected keys          | [AAL3](#aal3)                                                                     |
| Any level           | Set session lifetimes, and require reauthentication at the limits yourself               | [Session lifetimes and reauthentication](#session-lifetimes-and-reauthentication) |
| Any level           | Keep the failure ceiling at or below 100, and have a disabled factor bound again         | [Failure ceiling](#failure-ceiling)                                               |
| Any level           | Hold a new factor to the account's level, and notify the person from the events          | [Binding a factor](#binding-a-factor)                                             |
| Recovery codes      | Lengthen the codes, take one only after a bound factor, replace a set, notify the person | [Recovery codes](#recovery-codes)                                                 |

## Unclassified evidence

When the proofs cannot support a level, the level is `unclassified`, and `unclassified` meets no level requirement. That
is the answer for an email code alone, as an email code is not an out-of-band authenticator (3.1.3.1) and establishes no
level of its own, and for a first factor that is unknown or untrusted: no combination is accepted after one, so the
session cannot satisfy any non-empty requirement until its first factor is known (see [Failing
closed](assurance.md#failing-closed)). An empty requirement asks for nothing and is met without evidence, so bare `mfa`
admits an otherwise eligible caller under `never`, or under `enrolled` with no confirmed factor; hold a route to a level
with `mfa:level=aal2`.

Alone, an application declares `first_factor`, or binds a `Contracts\FirstFactorResolver`, and the configuration check
refuses one with neither. A declaration describes what the guard does, and nothing checks it against what the guard
really did, so it must be true. An external provider's first factor establishes no level of its own either: the further
proof's level applies, unless you rebind the policy to trust what the provider reports.

## Factor types

Enable, in each application's `types`, only what the level you claim can use. The default classification is in
[Classification](assurance.md#classification), and it is worth reading whichever first factor you use, as the second
factor alone does not decide the level:

- After a password, TOTP and a passkey reach AAL2 (2.2.1: two separate factors). SMS reaches AAL2 marked restricted. An
  email code is accepted but is not multifactor, and the session stays at AAL1 from the password.
- After a phone or email code, which are both something you have, only a passkey that observed user verification reaches
  AAL2, as a multi-factor authenticator on its own.

An accepted additional verification is not a level. `requirement => 'always'` and bare `mfa` ask for an additional
verification, which an email code meets, so ask for the level where you claim it: `mfa:level=aal2` on a route (see [The
forms](middleware.md#the-forms)), or `Requirement::none()->withMinimumLevel(AssuranceLevel::AAL2)` from an identity, a
tenant or an operation (see [Requirements and step-up](requirements.md)).

## Restricted SMS

SMS is the one restricted authenticator (3.1.3.3). The package marks a session that relies on it: `Assurance\Evaluation`
has `restricted`, from the bound `Contracts\RequirementCheck`, and a session that reaches its level without the SMS code
is not marked. It marks the session and offers nothing else: the duties of 3.2.9 are yours.

- Offer at least one unrestricted alternative at the level you claim, such as `totp` beside `sms` in the application's
  `types`.
- Give people meaningful notice of the risk and of the alternatives. The package sends nothing.
- Address the additional risk in your risk assessment.
- Have a plan to migrate away if the restricted authenticator stops being acceptable.

The package does not see a SIM change or a number being ported, which 3.1.3.3 suggests weighing. Changing a phone number
is enrolling a new factor (see [Replacing a factor](enrollment.md#replacing-a-factor)), so the rules of
[binding](#binding-a-factor) apply to it.

## Phishing resistance

At AAL2 you must offer at least one phishing-resistant option (2.2.2). A manually entered output is not
phishing-resistant (3.2.5), which rules out TOTP, delivered codes and recovery codes, so the option is a passkey. It
comes through a bound `Contracts\PasskeyGateway` and `passkey` in the application's `types`. The default gateway makes
passkeys unavailable, and the configuration check refuses an application that enables the type while it is bound (see
[Passkeys](extending.md#passkeys)).

Offering the option does not in general require anyone to use it. The exception is federal: agencies must require
phishing-resistant authentication of staff, contractors and partners accessing federal information systems (2.2.2).
Where you do require it, ask for the part: `Requirement::none()->withPhishingResistance()`, from an identity, a tenant
or an operation. A combination is
phishing-resistant only when a proof observed it, as `ObservedProperties::$phishingResistance` records, never because of
its type.

A syncable passkey's key is inherently exportable, so it is usable at AAL2 or below (3.2.13). What its assertion
observed is on the proof's properties, `backupEligibility` and `backupState` among them.

## AAL3

The default policy never reports AAL3, which needs hardware-protected keys (2.3.2, 3.1.6.1) it cannot see without
attestation, so a requirement for `aal3` is never met under it. To claim it, bind a `Contracts\CombinationPolicy` of
your own that rates evidence it can trust (see [Rebinding the policy](assurance.md#rebinding-the-policy)), with a
gateway that reports `keyProtection` from that evidence.

## Session lifetimes and reauthentication

Three things are easy to run together, and only the first is the package's:

- **The level** of the authenticators, which the package reports.
- **The session's lifetime**, which the guard or an authentication layer enforces.
- **Reauthentication**, a person showing they are present again, which your application requires.

The limits, with reauthentication resetting both timeouts and either expiring ending the session (5.2):

| Level | Overall                    | Inactivity                   | Section |
|-------|----------------------------|------------------------------|---------|
| AAL1  | SHOULD be at most 30 days  | Not required                 | 2.1.3   |
| AAL2  | SHOULD be at most 24 hours | SHOULD be at most 1 hour     | 2.2.3   |
| AAL3  | SHALL be at most 12 hours  | SHOULD be at most 15 minutes | 2.3.3   |

With `laravel-authentication`, a session's lifetimes are `jwt.refresh_idle_ttl_minutes` and
`jwt.refresh_absolute_ttl_minutes`, set for the package or per guard. Their defaults are 90 and 180 days, far above
AAL2's limits, so an application claiming AAL2 lowers them. Lowering them bounds the session but does not show
reauthentication: a refresh moves the idle deadline without showing that the person was present (and renews no proof's
freshness), so your application must itself require reauthentication at the limits.

Standalone, Laravel's `session.lifetime` is an inactivity limit only, so you enforce the overall limit yourself.

A named operation with a maximum age bounds how long ago the person last proved a further factor on a route, as a
proof's age is measured from when it was made and a refresh renews nothing. Ending the session at the limit remains your
application's job:

```php
'freshness' => [
    'session.reauthenticated' => ['minimum_level' => ['level' => 'aal2', 'max_age' => 86400]],
],
```

```php
Route::middleware('mfa:operation=session.reauthenticated')->group(function () {
    // ...
});
```

A maximum age says how old a proof may be, and the proof is the one that completes the combination, usually the further
proof. A fresh further proof over an old first factor still passes, so a TOTP step-up made every day keeps this example
met on a password months old. It cannot measure inactivity, it does not end the session, and it applies only to the
routes that carry it.

## Failure ceiling

You may allow at most 100 consecutive failures, by disabling the authenticator past them (3.2.2). That is
`attempts.failure_ceiling`, default 100, and also the most the package allows; lowering it is fine. The other caps sit
far below it (see [Attempts and lockouts](attempts.md)).

The setting is not all of it. A disabled authenticator must also be bound again (4.1) to be usable, and a reset of a
retry count may not reach past the session making it: the level of the authenticator being reset may not exceed the
session's (3.2.2). The package does not meet these by itself, and no configuration changes that. Proving any other of
the identity's factors enables a factor the ceiling disabled, with nothing bound again and whatever that proof's level
(see [The counters](attempts.md#the-counters)), so an email code, at AAL1, enables a TOTP factor.

To claim a level, your application takes this on:

- **Record it.** From `FactorDisabled`, record `$event->factor->id` as needing to be bound again. The factor's own
  disabled state does not last, so your record decides.
- **Refuse it.** While the record stands, your routes leave the factor out of what they offer and refuse to send for or
  verify it. The package does not know of your record, so nothing else stops it.
- **Bind it again.** The person authenticates at the level [binding a factor](#binding-a-factor) asks for, enrols a
  replacement and removes the disabled factor (see [Replacing a factor](enrollment.md#replacing-a-factor)). Then clear
  the record.
- **Recover when they cannot.** A person who cannot reach that level goes through account recovery (3.2.2, 4.2; see
  [Recovery codes](#recovery-codes)), not another binding.
- **Hold resets to the session's level.** `Attempts\AttemptService::enableFactor()` clears a factor's count, so call it
  only from a session whose level reaches the factor's, and only with the record cleared.
- **Enabling is not rebinding.** `Mfa::enableFactor()` keeps the factor's count, so it grants no fresh run of guesses,
  but it does not stand for the binding these sections ask for: keep your record of the owed rebinding authoritative,
  and enable a factor only once it is cleared.

Do not delete the factor from the listener. `Mfa::removeFactor()` serves only an active session fresh enough for it,
which a failing sign-in is not. Deleting the row yourself skips the last factor policy, and under `requirement =>
'enrolled'` an identity left with no factor owes nothing, so someone guessing with a stolen password would turn the
requirement off.

## Binding a factor

To bind a new authenticator, the person authenticates at the lower of the account's highest available level and the
level the new authenticator will be used at, and is notified through something independent of the transaction (4.1.2.1).

- **The level.** `mfa.add_factor` asks by default for an additional verification within 900 seconds, which is not a
  level: an email code meets it. Where an account can reach AAL2, set it in the application's `freshness` block
  (`'mfa.add_factor' => ['minimum_level' => ['level' => 'aal2', 'max_age' => 900]]`), and the same for
  `mfa.remove_factor` and `mfa.generate_recovery_codes`. The application block applies to every identity, so an
  application with accounts that can reach only AAL1 binds a `Contracts\FreshnessGate` that decides by account.
- **The first factor.** With no factor yet, the first one is authorised by the first factor proved again through a bound
  `Contracts\Reauthenticator`, whose default refuses (see [What authorises a
  start](enrollment.md#what-authorises-a-start)). The bootstrap path is off by default, and anyone holding the first
  factor can take it.
- **The route.** A cookie-authenticated route that binds a factor needs CSRF protection (see
  [CSRF protection](middleware.md#csrf-protection)).
- **The notice.** The package sends none. Notify the person on a channel they already had from `EnrollmentStarted`,
  `FactorConfirmed`, `PasskeyAssociated`, `BootstrapEnrollmentCompleted` and `FactorRemoved` (see [Events](events.md)).

## Recovery codes

A recovery code is treated as a look-up secret, something you have and not phishing-resistant (3.1.2). The package draws
codes with PHP's cryptographically secure generator (3.1.2.1 asks for an approved one), makes each single use, counts it
against the attempt caps, and stores it with your application's Laravel hasher (3.1.2.2), salted, as a code below 112
bits requires. Choose a generator and a hashing driver your assessment accepts (see
[Hashing cost](recovery-codes.md#hashing-cost)).

Used for account recovery, a saved recovery code has at least 64 bits, is hashed, is invalidated after use with a new
one issued, and recovery notifies the person (4.2). The default code of 13 characters from an alphabet of 32 is 65 bits,
which meets the first of these, but only part of it is the package's to do:

- Keep the code at 64 bits. If you change `recovery_codes.length` or `recovery_codes.alphabet`,
  `length × log2(alphabet size)` must still reach 64, as the configuration check enforces only 40 bits (13 decimal
  digits pass it at about 43).
- Issue the replacement. The package marks a used code used and issues none in its place. `Mfa::generateRecoveryCodes()`
  replaces the whole set, and only on a session fresh enough for it, so prompt for it from `RecoveryCodeUsed` and
  `RecoveryCodesLow`.
- Send the notification, from `RecoveryCodeUsed`, `RecoveryCodesGenerated` and `FactorsReset`. The package sends none.
- Take a code only after a bound factor. An account that can reach AAL2 recovers with two recovery codes from different
  methods, one recovery code plus authentication with a bound single-factor authenticator, or repeated identity proofing
  (4.2). A code redeemed after a password meets the second. A code redeemed after an email code does not, as email is
  not an authenticator (3.1.3.1), and nor does one after a first factor that is not bound to the account. The default
  policy still accepts both as an additional verification, so an application claiming AAL2 must not treat them as
  recovery: the two reach AAL1 at most, so `mfa:level=aal2` and an `aal2` entry for `mfa.add_factor` refuse them, while
  bare `mfa` does not.

The application's `recovery_codes.level` is the level a session needs to be issued a set, `aal2` by default. Lowering it
is your decision to record, and has a consequence: by default a recovery code after a password reaches AAL2, so a
session below AAL2 could then issue itself what reaches AAL2, and an email code would be enough to obtain it. Claim no
more than that weakest path supports.

Lost-factor recovery by someone else (`Mfa::resetIdentity()`) leaves the identity proofing to you (see
[Resetting an identity](lifecycle.md#resetting-an-identity)).

## What the package holds to already

These are always on, and cannot be turned off:

| Requirement                                                      | Section | How                                                                 |
|------------------------------------------------------------------|---------|---------------------------------------------------------------------|
| An OTP accepted once while valid, from a key of 112 bits or more | 3.1.4   | Each TOTP time step once per factor; a secret of at least 160 bits  |
| Look-up secrets single use, rate limited, salted and hashed      | 3.1.2.2 | One attempt against the whole unused set, under the identity's caps |
| A refresh renews no authentication                               | 5.2     | Only a proof's own time counts                                      |
