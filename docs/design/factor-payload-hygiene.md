# Factor Payload Hygiene

## Purpose

This note records the rule that a `Factor` row never leaves the database with its sensitive fields intact. Secrets are
encrypted at rest, left out of default Eloquent serialisation, and projected through a masked summary before an
exception payload, a JSON body or a log sees them. Delivered codes are not on the factor at all: they are kept as keyed
hashes in a table of their own (see [Delivered Codes](delivered-codes.md)).

Exception responses reach the browser, are rendered into HTML and are often captured by third-party logging and error
reporting, so a leak here is a leak everywhere downstream.

## Invariants

- `Factor::$secret` is a `text` column cast `encrypted` on the shipped model. It holds long-lived material (TOTP keys).
  Recovery codes are not factors: they live in a table of their own, as salted hashes (see
  [Recovery Codes](recovery-codes.md)).
- The model's `$hidden` lists it with the full `destination` and the `credential_reference`, so Eloquent's default
  array and JSON serialisation omit them. A factor dumped through `toArray()` or `->toJson()` shows no secret, no code
  and no full destination.
- `InsufficientAuthenticationException` carries no `Factor` instance, and neither does any event (see
  [Event Catalogue](event-catalog.md)): they carry `FactorSummary` values. `FactorSummary` is final, readonly and
  `JsonSerializable`.
- `FactorSummary` has exactly eight fields: `id`, `type`, `label`, `maskedDestination`, `status`, `preferred`,
  `lastUsedAt` and `disabled`. There is no `secret`, no `code`, no `attempts`, no credential reference and no raw
  `destination`.
- `FactorSummary::fromFactor()` masks the destination before the summary is built, so no caller can hand it an unmasked
  one: the mask is applied at the boundary.
- An email address keeps its domain and the first two characters of its local part, or the first one when the local
  part is three characters or fewer, with at least one `*` after them. Any other destination keeps its last four
  characters and masks the rest; one of four characters or fewer is fully masked.
- `jsonSerialize()` emits snake_case keys (`id`, `type`, `label`, `masked_destination`, `status`, `preferred`,
  `last_used_at`, `disabled`), the status as its value and `last_used_at` as ISO-8601, so consumers get a stable shape.

## Success Path

- A request reaches the `mfa` middleware and falls short. `Verification\FactorOffers::offered()` maps each factor it
  offers through `FactorSummary::fromFactor()`.
- `fromFactor()` casts the factor's identifier to a string (an empty string for one that is neither a string nor an
  integer), copies the type, label, status, preference and last use as they are, and masks the destination with
  `mask()`.
- The summaries are handed to `InsufficientAuthenticationException`. Laravel renders it with its message alone; an
  application that renders `toArray()` sends only the summaries' fields.
- A full `Factor` record dumped by admin tooling or debug output omits `secret`, `destination` and
  `credential_reference` by its `$hidden` list, before any summary is involved.

## Failure / Edge Cases

- An identifier that is neither a string nor an integer (a bug, or a custom factor model) becomes an empty string in
  the summary. The summary still serialises and the list still renders, and the broken row can be identified.
- A `null` or empty destination is kept as it is; only a non-empty string is masked. A factor with no destination
  (TOTP) has a `null` masked destination.
- An email address is split at its first `@`: the part before it is masked, and everything after it, any further `@`
  included, is kept as the domain.
- Any destination without an `@`, a phone number or a custom shape, is masked the same way. One of four characters or
  fewer is fully masked, so a short credential is never shown whole.
- `FactorSummary` is final, so it cannot be subclassed to add fields that bypass the mask. A custom projection is a
  class of its own, with its own rules.
- `$hidden` protects default serialisation, not explicit access. Code that reads `$factor->secret` (admin tooling,
  tests) gets the decrypted plaintext, as encryption at rest intends, and must not send it over the wire.

## Implementation Anchors

- `src/Factors/FactorSummary.php`: constructor, `fromFactor()`, `jsonSerialize()`, `mask()`, `maskEmail()`,
  `maskOpaque()`.
- `src/Models/Factor.php`: `$casts` (including `'secret' => 'encrypted'`) and `$hidden`.
- `src/Exceptions/InsufficientAuthenticationException.php`: the exception's payload, keyed on `FactorSummary[]`.
- `src/Verification/FactorOffers.php`: `offered()`, the single choke point where factors are projected through the
  summary before the exception is thrown.
- `database/migrations/2026_04_15_000000_create_mfa_factors_table.php`: `secret` defined as a `text` column to
  accommodate ciphertext.

## Authoritative Tests

- `tests/Unit/Factors/FactorSummaryTest.php`
  `testIsFinalReadonlyClass`
- `tests/Unit/Factors/FactorSummaryTest.php`
  `testImplementsJsonSerializable`
- `tests/Unit/Factors/FactorSummaryTest.php`
  `testFromFactorCapturesAllFields`
- `tests/Unit/Factors/FactorSummaryTest.php`
  `testFromFactorCollapsesNonScalarIdentifierToEmptyString`
- `tests/Unit/Factors/FactorSummaryTest.php`
  `testMaskingKeepsNullDestinationAsNull`
- `tests/Unit/Factors/FactorSummaryTest.php`
  `testMaskingEmailWithShortSingleCharLocalPart`
- `tests/Unit/Factors/FactorSummaryTest.php`
  `testMaskingEmailWithFourCharLocalPart`
- `tests/Unit/Factors/FactorSummaryTest.php`
  `testMaskingEmailPreservesDomain`
- `tests/Unit/Factors/FactorSummaryTest.php`
  `testMaskingPhonePreservesLastFourDigits`
- `tests/Unit/Factors/FactorSummaryTest.php`
  `testMaskingShortStringsAreFullyMasked`
- `tests/Unit/Factors/FactorSummaryTest.php`
  `testJsonSerializeShapeWithLastUse`
- `tests/Unit/Factors/FactorSummaryTest.php`
  `testJsonEncodesViaJsonSerializable`
- `tests/Unit/Models/FactorTest.php`
  `testSecretRoundTripsThroughEncryption`
- `tests/Unit/Models/FactorTest.php`
  `testRawSecretColumnIsNotStoredAsPlaintext`
- `tests/Unit/Models/FactorTest.php`
  `testSecretIsHiddenFromSerialization`

## Change Triggers

Update this note when any of the following change:

- the `encrypted` cast on `secret`, or the `text` column type in the migration
- the `$hidden` list on the shipped `Factor` model
- the field set on `FactorSummary` or the snake-case JSON shape from `jsonSerialize()`
- the masking rules for email local-parts or opaque destinations
- the single-choke-point rule that exceptions only see factors via `FactorSummary::fromFactor()`
- whether `FactorSummary` remains final and readonly
