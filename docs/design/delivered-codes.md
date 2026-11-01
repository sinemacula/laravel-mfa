# Delivered Codes

## Purpose

This note records how the package sends and checks the codes of the email and SMS factor types on its own: what a code
is bound to, what is stored, how a resend, the cooldown, the attempt budget and the delivery caps hold under
concurrency, who delivers a code, and why a code is never kept or queued in clear.

## Invariants

- A code belongs to a challenge: one row of the codes table, bound to the factor and to a binding, a
  `Proofs\ProofBinding` of the identity (type and key), the application, the session and the purpose (`sign_in`,
  `reauthenticate`, `step_up` or `enrollment`). A code checked against any other factor, identity, application,
  session or purpose is `missing`, even when its challenge is named, and such a check counts no attempt against it.
- The code is `length` digits from `random_int()`, zero-padded, stored only as `HMAC-SHA256(key', "code\0challenge
  id\0issue\0factor id\0identity type\0identity key\0application\0session id\0purpose\0code")`, compared with
  `hash_equals()`. The session is stored as `HMAC-SHA256(key'', session id)`, never the id itself, which is a bearer
  secret. `key'` and `key''` are separate derivations of `app.key`; rotating it only invalidates the codes outstanding.
  The factor row holds no code and no expiry, and the `Code` model hides the hash and the session digest.
- A challenge is open while its code is unused and it started less than `challenge_ttl_minutes` ago. Sending for a
  binding with an open challenge is a resend: the same row gets a new code under the next issue number, which makes the
  previous code stop matching at once, even when the new code has the same digits. The attempt count is kept, and the
  new code expires at `ttl_minutes` or the end of the challenge, whichever is sooner. With no open challenge, a send
  starts a new one.
- A resend waits out `resend_cooldown_seconds` since the challenge's last code. A challenge that has used up its
  `max_attempts` sends no more codes until it ends, so asking for a new code never brings new guesses.
- Every send, resends included, is refused while the factor has been sent `factor_send_limit` codes, or the identity
  `identity_send_limit` across its factors, within `send_window_minutes`, across every session. A refusal answers
  `sending_capped` with the seconds until another code may be sent.
- Sending runs in the identity's factor state transaction (see [Storage and Transactions](storage-and-transactions.md)),
  so the sends of one identity are serialised and the counts the caps read cannot be overrun by parallel requests. The
  factor is read again under the lock; one a concurrent change removed answers `not_found`.
- The code is stored first, then delivered by the factor's driver (`Contracts\CodeDeliveryDriver::deliver()`) inside
  the same transaction, so a delivery that throws keeps no code and spends no cooldown or cap. `CodeSent` is dispatched
  once the transaction commits, with the factor's summary (its masked destination), the purpose and the challenge's id.
- A check reads the challenge on the write connection: the one named, or the binding's latest. No challenge is
  `missing`; a used one is `replayed` for its last code and `missing` for any other; an expired code (`expires_at <=
  now`) is `expired`; a challenge with `attempts >= max_attempts` is `exhausted`; none of these counts an attempt.
  Otherwise the attempt is counted before anything is compared, by `UPDATE ... SET attempts = attempts + 1 WHERE id AND
  sends AND consumed_at IS NULL AND expires_at > now AND attempts < max`. A check whose increment matched no row never
  compares: it answers from a fresh read (`exhausted` or `expired` when that issue now is, otherwise `invalid`). A
  matching code is accepted only when `UPDATE ... SET consumed_at = now WHERE id AND sends AND consumed_at IS NULL`
  changed the row, so of two correct submissions exactly one is accepted.
- `invalid` answers the failure reason `invalid_code`, `replayed` answers `replayed`, and `missing`, `expired` and
  `exhausted` answer `expired`: there is no live code to check against. The detail that tells them apart stays in the
  failure event.
- Neither a send nor a check resets a factor's failure count or lifts its lockout.
- Every time is a whole second, and one `now` is used per operation.
- Delivery goes through contracts the application binds: `Contracts\SmsSender` (a phone number and the message, the
  configured `sms_message` with `:code` replaced) and `Contracts\EmailSender` (an address and the configured
  `MfaCodeMessage` class, with the whole minutes the code has left). The package ships no provider: the defaults,
  `Codes\NullSmsSender` and `Codes\NullEmailSender`, throw `SenderNotConfiguredException`, and the configuration check
  refuses an application that enables `sms` or `email` while its sender is the default, or while no `app.key` is set.
  `Codes\MailEmailSender` sends through Laravel's mailer for an application that binds it.
- `MfaCodeMessage`, and every subclass of it, implements `ShouldBeEncrypted`, so whenever it is queued, by a sender that
  queues it or because the class is queueable, the queue stores its payload encrypted with the application key, never
  the code in clear.
- A driver that delivers codes is not asked to send or check them with the factor alone: its `issueChallenge()`,
  `verify()` and `confirm()` throw a `LogicException`, since a code bound to nothing could be accepted anywhere.

## Success Path

- `Mfa::challenge('email', $factor)` (or with `Purpose::STEP_UP`): identity and ownership checks; the binding of this
  request (the identity, the application a bound `ApplicationResolver` names or the default guard's name, the Laravel
  session's id, the purpose); `CodeService::send()`: the factor state transaction, the identity's and the factor's
  sends counted, a challenge started or resent, the code delivered through the bound `EmailSender`, `CodeSent` queued
  for the commit; `MfaChallengeIssued`; a `Codes\SendResult` with the challenge's id and expiry.
- `Mfa::verify('email', $factor, $code)` with the same purpose: `CodeService::check()`: the read, the counting
  `UPDATE`, the comparison and the using `UPDATE`; then the factor's verification is recorded as for any type.

## Failure / Edge Cases

- A resend within the cooldown, a send for an exhausted challenge, or one past a cap: `SendResult::refused()` with
  `sending_capped` and the wait; nothing is delivered and `MfaChallengeIssued` is not dispatched.
- A factor with no destination: `MissingDestinationException`, before the transport; the code is not kept.
- No sender bound: `SenderNotConfiguredException` from the default sender; the code is not kept. The configuration check
  normally refuses this before any send.
- A factor that is not a stored Eloquent factor: `UnsupportedFactorException`. A binding that names another identity
  than the factor's owner: `InvalidArgumentException`. Neither reads anything.
- A code sent inside a transaction that rolls back is gone with it, and `CodeSent` is never dispatched.
- Expired and used challenges stay in the table, for pruning to remove past `lifecycle.prune_after_days`; they still
  count towards the caps while their last send is inside the send window.

## Implementation Anchors

- `src/Codes/DeliveredCodes.php` (engine), `src/Codes/CodeKeys.php`, `src/Codes/CodeService.php`,
  `src/Codes/CodeCheck.php`, `src/Codes/SendResult.php`, `src/Codes/IssuedCode.php`, `src/Codes/CodeSettings.php`.
- `src/Contracts/CodeDeliveryDriver.php`, `src/Drivers/AbstractCodeDriver.php`, `src/Drivers/EmailDriver.php`,
  `src/Drivers/SmsDriver.php`.
- `src/Contracts/SmsSender.php`, `src/Contracts/EmailSender.php`, `src/Codes/NullSmsSender.php`,
  `src/Codes/NullEmailSender.php`, `src/Codes/MailEmailSender.php`, `src/Codes/MfaCodeMessage.php`.
- `src/Testing/FakeSmsSender.php`, `src/Testing/FakeEmailSender.php`.
- `src/Verification/VerificationService.php`: the binding of a request and the routing of delivered codes.

## Authoritative Tests

- `tests/Unit/Codes/DeliveredCodesTest.php`
- `tests/Unit/Codes/CodeServiceTest.php`
- `tests/Unit/Codes/CodeKeysTest.php`
- `tests/Unit/Codes/MfaCodeMessageQueueTest.php`
- `tests/Feature/OtpLifecycleTest.php`
- `tests/Unit/Config/ConfigurationValidatorTest.php`

## Change Triggers

- A change to what a code is bound to, how it is hashed, or the key it is hashed with.
- A change to the resend, cooldown, attempt or cap rules, or to the statements that apply them.
- Delivery moving out of the factor state transaction, or onto a queue the package dispatches.
- An authentication layer's challenges taking over the codes (`Contracts\ChallengeGateway`).
