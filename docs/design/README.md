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
- `combination-policy.md`: how the default combination policy decides which factors may follow a first factor, how it
  classifies a session's proofs (accepted, multifactor, level, phishing resistance, restriction, `amr`), and how it
  judges each requirement part and its maximum age.
- `verification-lifecycle-and-events.md`: the five lifecycle events (`MfaChallengeIssued`, `MfaVerified`,
  `MfaVerificationFailed`, `MfaFactorEnrolled`, `MfaFactorDisabled`), who dispatches them, and the exact ordering
  against driver calls and store writes.
- `application-configuration.md`: the shape of the configuration (one block per application, one per capability),
  the settings classes that read and check each block on every call, the bounds they enforce, and the check of the
  whole configuration and the bindings it needs at boot, at manager resolution and from `mfa:check`.
- `storage-and-transactions.md`: the storage connection every table and shipped model uses, the refusal of a model on
  another connection, and the one transaction and lock order of every change to an identity's whole factor state.
- `schema-and-models.md`: every table and column, the models and the two an application may replace, the identity
  contract and its trait, forgetting a deleted identity, and the guard every operation on a factor starts with.
- `event-catalogue.md`: the events the flows dispatch, their payloads and context, and their dispatch after the commit.
- `seam-contracts.md`: the contracts declared for the seams with an authentication layer and the application, what
  each answers and what a fail-closed answer is, and the pending session and passkey assertion values they carry.
- `backup-code-consumption.md`: how backup codes are stored hashed, why consumption and rotation run under the owner's
  factor state lock, and the atomic-replace guarantee on rotation.
- `attempts-and-lockout.md`: the per-factor rate-limit state machine on `attempts` / `locked_until` /
  `last_attempted_at`, including how OTP drivers reset attempts paired with a fresh code.
- `per-device-verification-and-step-up.md`: the `MfaVerificationStore` seam, the default session-scoped
  implementation, the `mfa:N` step-up route-parameter contract, and the fail-closed rules inside `hasExpired()`.
- `factor-payload-hygiene.md`: encryption at rest for `secret` / `code`, the `FactorSummary` projection used on
  exception payloads, and the destination-masking rules.

These documents are secondary to the code and tests, not a replacement for them. If a note and a cited test disagree,
the test should be treated as authoritative until the mismatch is resolved.
