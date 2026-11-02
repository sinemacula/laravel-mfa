# Design Notes

These notes document the package's security and lifecycle contracts that are easy to miss if you only read the
quick-start material or skim the test suite.

Each note is intentionally short and follows the same structure:

- `Purpose`
- `Invariants`
- `Success Path`
- `Failure / Edge Cases`
- `Seams Left`, where a note has parts with nothing yet behind them
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
- `verification-lifecycle-and-events.md`: how a verification runs: the one binding captured and checked again under the
  lock, the routes and their counts, the seam as the last write, re-evaluating the requirement, and the order of the
  events against the commit.
- `application-configuration.md`: the shape of the configuration (one block per application, one per capability),
  the settings classes that read and check each block on every call, the bounds they enforce, and the check of the
  whole configuration and the bindings it needs at boot, at manager resolution and from `mfa:check`.
- `storage-and-transactions.md`: the storage connection every table and shipped model uses, the refusal of a model on
  another connection, the one transaction and lock order of every change to an identity's whole factor state, the lock
  order of each flow, and what the evidence for it does and does not show.
- `long-running-processes.md`: what the container keeps under Octane and in a queue worker, how the listeners reach the
  request at hand, why nothing is `scoped()`, and what the tests prove and do not.
- `schema-and-models.md`: every table and column, the models and the two an application may replace, the identity
  contract and its trait, forgetting a deleted identity, and the guard every operation on a factor starts with.
- `event-catalog.md`: the events the flows dispatch, their payloads and context, and their dispatch after the commit.
- `seam-contracts.md`: the contracts declared for the seams with an authentication layer and the application, what
  each answers, its fail-closed default, what the authentication layer provides for it, the calls that layer makes back
  into this package (the challenge counters and the passkey change gate), the helpers' pending-action checks, and the
  contract test kit an adapter proves itself with.
- `passkeys.md`: how a passkey becomes a factor through its association record, the change gate every registration,
  removal and change of a passkey passes through, and the assertions a passkey factor is verified with.
- `requirements-and-freshness.md`: how a sign-in's requirement is composed from the application's mode, the identity,
  a re-enrolment obligation and an active tenant, how a session's proofs are checked against a requirement, and how a
  named operation's freshness is judged, the stricter of the package's and the caller's setting applying.
- `route-gate.md`: the `mfa` middleware that judges a route's whole requirement, who it refuses, the exempt marker, the
  exception it raises, the authentication context, and why what a completion returns can never reach a response if the
  commit fails.
- `factor-lifecycle.md`: what happens to a factor after it is enrolled: how it is listed, what a removal checks before
  and under the lock, what a reset does and in which order, what unlocking leaves alone, and what pruning may delete.
- `enrollment.md`: how a factor is enrolled: what authorises a start, why a grant's expiry is taken once from what
  authorised it, what a grant is bound to, what a confirmation checks again inside its transaction, and what it does for
  the session.
- `totp.md`: how TOTP codes are made and checked, the secret and parameters each factor is enrolled with, the
  window, and the compare-and-set that accepts each time step once per factor, also under concurrency.
- `recovery-codes.md`: how recovery codes are drawn and stored as salted hashes, why a redemption checks the whole
  unused set as one attempt with the same work whichever code matches, how a new set replaces the old one with no
  moment when both work or neither exists, and how the set goes with the last factor.
- `attempts-and-lockout.md`: the durable failure counts on the factor and identity rows, the temporary throttles of
  the identity and the address, when each locks and what resets it, the failure ceiling, and why parallel guesses
  cannot overrun a cap.
- `delivered-codes.md`: the email and SMS codes the package sends and checks on its own: what a code is bound to, its
  keyed hash, resends, the cooldown, the attempt budget and the delivery caps, the sender contracts, and the encrypted
  queued message.
- `consumer-messages.md`: the words that can reach a consumer, how each is translated and in which locale, the shipped
  English when a translation cannot be used, a line that loses its code, and what is deliberately not translated.
- `factor-route-binding.md`: how a route parameter of the factor model binds only within the caller's identity, from
  whichever credential the route uses, through the model's own lookup, and what the binding does not reach.
- `testing-helpers.md`: the public helpers for an application's tests, what acting as a verified identity arranges and
  checks, and which test helpers stay private to the package.
- `proof-store.md`: the `ProofStore` seam and its session-backed default, how a sign-in begins and ends (Laravel's
  events or the guard hooks), what makes a recorded proof stop counting, the verification generation, and how the
  `mfa` middleware judges a request on the proofs.
- `factor-payload-hygiene.md`: encryption at rest for `secret`, the `FactorSummary` projection used on
  exception payloads, and the destination-masking rules.
- `secrets-in-responses-and-logs.md`: the value secrets are meant to be returned in and what it refuses, the response
  helper and `mfa.no-store` middleware that send them uncached, the redaction of secrets, codes and destinations from
  logs, exception messages and traces, delivery failures included, and TOTP secrets surviving a key rotation.

These documents are secondary to the code and tests, not a replacement for them. If a note and a cited test disagree,
the test should be treated as authoritative until the mismatch is resolved.
