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

- `capability-services.md`: how the package is organised by capability, the manager as a one-line delegation to each
  capability's service, the `*Bindings` class each capability registers its wiring through, and what the services
  share.
- `assurance-vocabulary.md`: the values assurance is described with (channels, observed properties, proofs,
  levels, requirements and their composition, evaluations, verification results), what each refuses, their serialised
  forms, and the enums whose values are stable names.
- `verification-lifecycle-and-events.md`: the five lifecycle events (`MfaChallengeIssued`, `MfaVerified`,
  `MfaVerificationFailed`, `MfaFactorEnrolled`, `MfaFactorDisabled`), who dispatches them, and the exact ordering
  against driver calls and store writes.
- `storage-and-transactions.md`: the storage connection every table and shipped model uses, the refusal of a model on
  another connection, and the one transaction and lock order of every change to an identity's whole factor state.
- `seam-contracts.md`: the contracts declared for the seams with an authentication layer and the application, what
  each answers and what a fail-closed answer is, and the pending session and passkey assertion values they carry.
- `backup-code-consumption.md`: how backup codes are stored hashed, why consumption and rotation run under the owner's
  factor state lock, and the atomic-replace guarantee on rotation.
- `attempts-and-lockout.md`: the per-factor rate-limit state machine on `attempts` / `locked_until` /
  `last_attempted_at`, including how OTP drivers reset attempts paired with a fresh code.
- `per-device-verification-and-step-up.md`: the `MfaVerificationStore` seam, the default session-scoped
  implementation, the `mfa:N` step-up route-parameter contract, and the fail-closed rules inside `hasExpired()`.
- `factor-payload-hygiene.md`: encryption at rest for `secret` / `code`, the `FactorSummary` projection used on
  exception payloads, and the recipient-masking rules.

These documents are secondary to the code and tests, not a replacement for them. If a note and a cited test disagree,
the test should be treated as authoritative until the mismatch is resolved.
