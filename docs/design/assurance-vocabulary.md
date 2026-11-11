# Assurance Vocabulary

## Purpose

This note records the values the package describes assurance with: channels, observed properties, proofs and their
bindings, assurance levels, requirements, evaluations, verification results, and the enums whose values are stable
names (failure reasons, proof kinds, purposes, channel kinds, key protections, requirement parts, operations and
pending actions). They are this package's own types; a sibling package maps them to its own rather than this package
referencing another's.

## Invariants

- Every value is `final readonly` and holds no behaviour beyond checking itself. A value that contradicts itself is
  refused with an `InvalidArgumentException` when it is built, so one that exists is consistent and a consumer never
  re-checks it.
- Nothing observed is assumed. `ObservedProperties` holds `null` for each property not observed and never defaults to
  true, so a level, an `amr` value or a context key is only derived from what a proof observed, never from a factor's
  type or from configuration.
- A channel's reference is never blank, and a password or an unknown channel takes none; those two carry first
  factors only, never an enrolled factor.
- A proof's parts agree with its kind: a recovery code has no channel and every other kind has one; an additional
  factor names the factor it was made with and never travels on a password or unknown channel; a first factor carries
  `sign_in` and a reauthentication with it `reauthenticate`; a recovery code never carries `enrollment`, as it cannot
  confirm an enrolment; the verification generation is never negative; a binding's identity type and key, application
  and session are never blank.
- `AssuranceLevel::meets()` orders `aal1` below `aal2` below `aal3`, and `unclassified` meets no minimum.
- A requirement is built from `Requirement::none()` and is immutable: each `with...()` returns a new requirement. A
  maximum age is at least one second, and `unclassified` cannot be asked for. `Requirement::strictest()` asks for every
  part any input asks for, the highest minimum level and, per part, the shortest maximum age, where no maximum age
  allows any; the result is the same in any order of its inputs, and a session that meets it meets each input.
- An evaluation's `amr` values are never blank or repeated, and a requirement part is listed at most once across met
  and unmet.
- An evaluation reports nothing its own answers rule out: `additional_verification` is met only when the combination
  is accepted or multifactor, `multifactor` only when it is multifactor, `phishing_resistance` only when it is
  phishing-resistant, and `minimum_level` never at `unclassified`; `mfa` is in `amr` only for a multifactor
  combination, and `mca` only for an accepted one that is not. A replaced combination policy therefore cannot report
  more than it found.
- A verification result is verified (a proof and its evaluation) or failed (a reason and a non-blank detail), never
  both. Only a `locked` failure carries the time the lockout lifts, and none at the failure ceiling, which does not lift
  by itself.
- The serialised forms use snake_case keys and enum values. A proof's time is ISO-8601 to the microsecond with its
  offset. Reading a form back (`fromArray()` on `Channel`, `ObservedProperties`, `ProofBinding`, `Proof` and
  `Requirement`) refuses a required field that is missing or of another type, and any field the form does not know,
  rather than building a partial value; a nullable field may be left out and reads as `null`, and a missing observed
  property reads as not observed. A requirement refuses an unknown part, and an unknown field within a part, rather
  than dropping it, so a mistyped `max_age` never removes a freshness limit.
- The enum values are stable names once released, and each is pinned by a test.

## Success Path

- A proof is built with its kind, method, channel, reference, observed properties, time, binding and the identity's
  verification generation, and checked as it is built. `toArray()` gives the form a store keeps, and
  `Proof::fromArray()` reads it back to an equal proof.
- A requirement is built from `Requirement::none()` part by part, or read from its serialised form, and the parts from
  several sources are composed with `Requirement::strictest()`.
- An evaluation of a session's proofs says what the combination is and which parts of the requirement it meets, and a
  verification result carries the proof with its evaluation, or a `FailureReason` with its internal detail.
- `Mfa::verify()` answers with that result. Its `amr` is the proof's own, leaving out `mfa`, which only the evaluation
  can report, and it also holds the type proved and what the completion seam returned, opaque to this package. It keeps
  all of that out of every dump and JSON, and refuses to be serialised.
- A channel holds its reference as a `\SensitiveParameterValue`, read through `reference()`, so no dump of a proof shows
  a full destination; only the stored form, `toArray()`, gives it up.

## Failure / Edge Cases

- A recovery code is not a factor, so its proof has no channel rather than an unknown one: an unknown channel means a
  first factor that establishes no independence, which a recovery code is not.
- A proof's serialised form holds the channel's full destination. It is for storing a proof, never for an event, a log
  or a response, which carry a factor's masked summary.
- A serialised time that only parses by overflowing (a thirteenth month) is refused, since the read time is formatted
  again and compared with the input.
- A failure reason says what a caller may be told; a factor that does not exist and one that belongs to someone else
  both answer `not_found`, and only the detail, in events and logs, says which.
- A delivered code with no live challenge (none sent, out of attempts or expired) fails as `expired`, and its detail
  says which.
- `strictest()` with no inputs is the requirement that asks for nothing.

## Implementation Anchors

- `src/Assurance/Channel.php`, `src/Assurance/ObservedProperties.php`, `src/Assurance/Evaluation.php`.
- `src/Proofs/Proof.php`, `src/Proofs/ProofBinding.php`.
- `src/Requirements/Requirement.php`: `strictest()`, `fromArray()`, `with()`.
- `src/Verification/VerificationResult.php`.
- `src/Enums/FailureReason.php`, `src/Enums/ChannelKind.php`, `src/Enums/ProofKind.php`, `src/Enums/Purpose.php`,
  `src/Enums/KeyProtection.php`, `src/Enums/AssuranceLevel.php`, `src/Enums/RequirementPart.php`,
  `src/Enums/Operation.php`, `src/Enums/PendingAction.php`.
- `src/Support/SerializedFields.php`: the typed reader every `fromArray()` uses.

## Authoritative Tests

- `tests/Unit/Proofs/ProofTest.php`
  `testAnInvalidProofIsRefused`
- `tests/Unit/Proofs/ProofTest.php`
  `testAProofRoundTrips`
- `tests/Unit/Requirements/RequirementTest.php`
  `testTheStrictestRequirement`
- `tests/Unit/Requirements/RequirementTest.php`
  `testAMalformedRequirementIsRefused`
- `tests/Unit/Assurance/ObservedPropertiesTest.php`
  `testNothingIsObservedByDefault`
- `tests/Unit/Assurance/EvaluationTest.php`
  `testAnInconsistentEvaluationIsRefused`
- `tests/Unit/Assurance/EvaluationTest.php`
  `testAContradictoryEvaluationIsRefused`
- `tests/Unit/Support/SerializedFieldsTest.php`
  `testAnUnknownFieldIsRefused`
- `tests/Unit/Verification/VerificationResultTest.php`
  `testALockoutMayLackItsTime`
- `tests/Unit/Enums/FailureReasonTest.php`
  `testFailureReasonsAreTheReportedValues`
- `tests/Unit/Enums/AssuranceLevelTest.php`
  `testALevelMeetsTheMinimumsAtOrBelowIt`

## Change Triggers

Update this note when any of the following change:

- a value's parts, or a rule it refuses on construction
- the composition rule of `Requirement::strictest()`
- the serialised form of a value, or what reading it back refuses
- an enum's cases or values
- whether a recovery code proof carries a channel
