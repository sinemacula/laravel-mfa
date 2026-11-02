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
- The code is `length` digits, each drawn with `random_int()`, stored only as `HMAC-SHA256(key', "code\0challenge
  id\0issue\0factor id\0identity type\0identity key\0application\0session id\0purpose\0code")`, compared with
  `hash_equals()`. The session is stored as `HMAC-SHA256(key'', session id)`, never the id itself, which is a bearer
  secret. `key'` and `key''` are separate derivations of `app.key`; rotating it only invalidates the codes outstanding.
  The factor row holds no code and no expiry, and the `Code` model hides the hash and the session digest.
- A challenge is open while its code is unused and it started less than `challenge_ttl_minutes` ago. Sending for a
  binding with an open challenge is a resend: the same row gets a new code under the next issue number, which makes the
  previous code stop matching at once. The new code is drawn again until its digits differ from the previous code's,
  which would otherwise still match under the new issue. The attempt count is kept, and the new code expires at
  `ttl_minutes` or the end of the challenge, whichever is sooner. With no open challenge, a send starts a new one.
- A resend waits out `resend_cooldown_seconds` since the challenge's last code. A challenge that has used up its
  `max_attempts` sends no more codes until it ends, so asking for a new code never brings new guesses.
- Every send, resends included, is refused while the factor has been sent `factor_send_limit` codes, or the identity
  `identity_send_limit` across its factors, within `send_window_minutes`, across every session. A challenge records the
  time of each of its sends (`sent_times`), and each send leaves the window on its own, a window after it was made, so
  a challenge's earlier sends stop counting while its later ones still do. A refusal answers `sending_capped` with the
  seconds until enough sends have left the window for one more.
- Sending runs in the identity's factor state transaction (see [Storage and Transactions](storage-and-transactions.md)),
  so the sends of one identity are serialised and the counts the caps read cannot be overrun by parallel requests. The
  factor is read again under the lock; one a concurrent change removed answers `not_found`. The send's time is read
  once the locks are held, so a send that waited for them starts its cooldown and its code's lifetime from when it was
  made, not from when it began waiting.
- The code is stored first, then delivered by the factor's driver (`Contracts\CodeDeliveryDriver::deliver()`) inside
  the same transaction, so a delivery that throws keeps no code and spends no cooldown or cap. `CodeSent` is dispatched
  by `Verification\ChallengeRequests` once the transaction commits, whichever gateway sent the code, with the factor's
  summary (its masked destination), the purpose and the challenge's id.
- A check reads the challenge on the write connection: the one named, or the binding's latest. No challenge is
  `missing`; a used one is `replayed` for its last code and `spent` for any other; an expired code (`expires_at <=
  now`) is `expired`; a challenge with `attempts >= max_attempts` is `exhausted`; none of these counts an attempt.
  Otherwise the attempt is counted before anything is compared, by `UPDATE ... SET attempts = attempts + 1 WHERE id AND
  sends AND consumed_at IS NULL AND expires_at > now AND attempts < max`. A check whose increment matched no row never
  compares: it answers from a fresh read (`spent` when another check used that issue, `exhausted` or `expired` when it
  now is, otherwise `invalid`). A matching code is accepted only when `UPDATE ... SET consumed_at = now WHERE id AND
  sends AND consumed_at IS NULL` changed the row, so of two correct submissions exactly one is accepted.
- `invalid` answers the failure reason `invalid_code`, `replayed` answers `replayed`, `spent`, `expired` and `exhausted`
  answer `expired`, since a known challenge has no live code to check against, and `missing` answers `not_found`. The
  detail that tells them apart stays internal. Every one of them is counted against the factor and the identity.
- Neither a send nor a check resets a factor's failure count or lifts its lockout.
- Every time is a whole second, and one `now` is used per operation.
- A code is bound to the request's Laravel session id. Sending and checking must run in the same started session: a
  stateless request has a new id each time, so a code sent in one is never found in the next, and a session
  regenerated between the send and the check leaves its code behind. Either answers `expired`.
- Delivery goes through contracts the application binds: `Contracts\SmsSender` (a phone number and the message, the
  configured `sms_message` with `:code` replaced) and `Contracts\EmailSender` (an address and the configured
  `MfaCodeMessage` class, with the whole minutes the code has left). The package ships no provider: the defaults,
  `Codes\NullSmsSender` and `Codes\NullEmailSender`, throw `SenderNotConfiguredException`, and the configuration check
  refuses an application that enables `sms` or `email` while its sender is the default, or while no `app.key` is set.
  `Codes\MailEmailSender` sends through Laravel's mailer for an application that binds it.
- `MfaCodeMessage`, and every subclass of it, implements `ShouldBeEncrypted`, so whenever it is queued, by a sender that
  queues it or because the class is queueable, the queue stores its payload encrypted with the application key, never
  the code in clear.
- A driver that delivers codes is not asked to check them with the factor alone: its `verify()` and `confirm()` throw a
  `LogicException`, since a code bound to nothing could be accepted anywhere.

## Success Path

- `Mfa::sendCode($factorId)`: the caller and its binding are captured (the identity, the application, the sign-in, the
  purpose), the factor state transaction opens and they are checked again, the factor is admitted, and the bound
  `ChallengeGateway` sends: by default `Codes\PackageChallengeGateway`, through `CodeService::send()`: the identity's
  and the factor's sends counted, a challenge started or resent, the code delivered through the bound `EmailSender`.
  `CodeSent` is queued for the commit, and the answer is a `Codes\SendResult` with the challenge's id and expiry.
- `Mfa::verify(Submission::challenge($factorId, $challengeId, $code))` under the same purpose, in the same sign-in: the
  gateway asks `ChallengeCounters::isUsable()`, `CodeService::check()` makes the read, the counting `UPDATE`, the
  comparison and the using `UPDATE`, and `ChallengeCounters::report()` counts the outcome against the factor and the
  identity in the same transaction, so a lockout refuses it before the challenge is read, spending none of its attempts,
  and the code's use and the count commit as one. A refusal by the completion seam rolls both back (see [Verification
  Lifecycle and Events](verification-lifecycle-and-events.md)).

## Failure / Edge Cases

- A resend within the cooldown, a send for an exhausted challenge, or one past a cap: `SendResult::refused()` with
  `sending_capped` and the wait; nothing is delivered and `CodeSent` is not dispatched.
- A factor with no destination: `MissingDestinationException`, before the transport; the code is not kept.
- No sender bound: `SenderNotConfiguredException` from the default sender; the code is not kept. The configuration check
  normally refuses this before any send.
- Any throwable from the driver's `deliver()`, the two above included, is caught around that call alone, scrubbed of the
  code and the factor's destination (see [Secrets in Responses and Logs](secrets-in-responses-and-logs.md)), and
  rethrown as `CodeDeliveryFailedException`, which names the factor's type and masked destination and keeps the
  scrubbed throwable as its previous one. The transaction rolls back, so the code is not kept.
- A factor that is not a stored Eloquent factor: `UnsupportedFactorException`. A binding that names another identity
  than the factor's owner: `InvalidArgumentException`. Neither reads anything.
- A code sent inside a transaction that rolls back is gone with it, and `CodeSent` is never dispatched.
- Expired and used challenges stay in the table, for pruning to remove past `lifecycle.prune_after_days`; their sends
  still count towards the caps while they are inside the send window.
- A verification in a session other than the one the code was sent in (a stateless request, or a regenerated session)
  finds no challenge and answers `expired`.

## Implementation Anchors

- `src/Codes/DeliveredCodes.php` (engine), `src/Codes/CodeKeys.php`, `src/Codes/CodeService.php`,
  `src/Enums/CodeCheck.php`, `src/Codes/SendResult.php`, `src/Codes/IssuedCode.php`, `src/Codes/CodeSettings.php`.
- `src/Contracts/CodeDeliveryDriver.php`, `src/Drivers/AbstractCodeDriver.php`, `src/Drivers/EmailDriver.php`,
  `src/Drivers/SmsDriver.php`.
- `src/Contracts/SmsSender.php`, `src/Contracts/EmailSender.php`, `src/Codes/NullSmsSender.php`,
  `src/Codes/NullEmailSender.php`, `src/Codes/MailEmailSender.php`, `src/Codes/MfaCodeMessage.php`.
- `src/Testing/FakeSmsSender.php`, `src/Testing/FakeEmailSender.php`, `src/Testing/FakeSenderBinding.php`.
- `src/Verification/VerificationService.php`: the binding of a request and the routing of delivered codes.
- `src/Attempts/AttemptService.php`: the attempt a check runs inside, and the lockouts that refuse it.

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
