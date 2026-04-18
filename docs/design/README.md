# Design Notes

These notes document the package's security and lifecycle contracts that are easy to miss if you only read the
quick-start material or skim the test suite.

Each note is intentionally short and follows the same structure:

- `Purpose`
- `Invariants`
- `Success Path`
- `Failure / Edge Cases`
- `Implementation Anchors`
- `Authoritative Tests`
- `Change Triggers`

The current note set is:

- `verification-lifecycle-and-events.md`: the five lifecycle events (`MfaChallengeIssued`, `MfaVerified`,
  `MfaVerificationFailed`, `MfaFactorEnrolled`, `MfaFactorDisabled`), who dispatches them, and the exact ordering
  against driver calls and store writes.
- `backup-code-consumption.md`: how backup codes are stored hashed, why consumption uses a pessimistic row lock on the
  factor model's own connection, and the atomic-replace guarantee on rotation.
- `attempts-and-lockout.md`: the per-factor rate-limit state machine on `attempts` / `locked_until` /
  `last_attempted_at`, including how OTP drivers reset attempts paired with a fresh code.
- `per-device-verification-and-step-up.md`: the `MfaVerificationStore` seam, the default session-scoped
  implementation, the `mfa:N` step-up route-parameter contract, and the fail-closed rules inside `hasExpired()`.
- `factor-payload-hygiene.md`: encryption at rest for `secret` / `code`, the `FactorSummary` projection used on
  exception payloads, and the recipient-masking rules.

These documents are secondary to the code and tests, not a replacement for them. If a note and a cited test disagree,
the test should be treated as authoritative until the mismatch is resolved.
