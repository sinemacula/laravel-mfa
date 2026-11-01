# Factor Payload Hygiene

## Purpose

This note records the rule that a `Factor` row never leaves the database with its sensitive fields intact. Secrets are
encrypted at rest, excluded from default Eloquent serialisation, and projected through a masked-destination summary
before any exception payload, JSON body, or log sink sees them. Delivered codes are not on the factor at all: they are
kept as keyed hashes in a table of their own (see [Delivered Codes](delivered-codes.md)).

The contract matters because exception responses are consumed by the browser, rendered into HTML, and frequently
captured by third-party logging and error-reporting tooling. A leak at this layer is a leak everywhere downstream.

## Invariants

- The `Factor::$secret` column is typed `text` and cast `encrypted` on the shipped model. It carries long-lived
  material (TOTP keys, SHA-256 digests of backup codes).
- It is listed in the model's `$hidden`, with the full `destination` and the `credential_reference`, so
  Eloquent's default array/JSON serialisation omits them. A consumer who accidentally dumps a factor through
  `toArray()` or `->toJson()` gets a payload with no secret, no code and no full destination.
- `MfaRequiredException` and `MfaExpiredException` do not carry `Factor` instances, and neither does any event (see
  [Event Catalogue](event-catalogue.md)). They carry `FactorSummary` values. `FactorSummary` is final, readonly, and
  `JsonSerializable`.
- `FactorSummary` exposes exactly seven fields: `id`, `type`, `label`, `maskedDestination`, `status`, `preferred` and
  `lastUsedAt`. There is no `secret`, no `code`, no `attempts`, no credential reference and no raw `destination`.
- Destination masking happens inside `FactorSummary::fromFactor()` before the summary is constructed. Consumers cannot
  accidentally hand an unmasked destination into the summary — the mask is applied at the boundary, not trusted to
  callers.
- Email masking keeps the domain intact and masks the local-part except for the leading two characters (or one, for a
  single-character local-part). Phone / opaque addresses keep the last four characters and mask the rest; strings of
  four characters or fewer are fully masked.
- `jsonSerialize()` emits snake-case keys (`id`, `type`, `label`, `masked_destination`, `status`, `preferred`,
  `last_used_at`), the status as its value and `last_used_at` as ISO-8601, so downstream consumers get a stable wire
  shape.

## Success Path

- A request reaches `RequireMfa`. If MFA is not set up, or has never been verified, or has expired,
  `resolveFactorSummaries()` maps each registered factor through `FactorSummary::fromFactor()`.
- `fromFactor()` stringifies the raw factor identifier (falling back to an empty string for non-scalar identifiers),
  copies the type, label, status, preference and last use verbatim, and masks the destination through the `mask()`
  helper.
- The masked summary list is handed to `MfaRequiredException` or `MfaExpiredException`. The consuming application
  renders the exception payload via its exception handler, and the JSON body ends up carrying only the seven safe
  fields.
- If a consumer dumps the full `Factor` record (admin tooling, debug output), the model's `$hidden` list ensures
  the default array representation omits `secret`, `destination` and `credential_reference` even before the
  summary layer runs.

## Failure / Edge Cases

- A non-scalar factor identifier (implementation bug, custom factor model) collapses to an empty string in the
  summary. This fails safe — the summary still serialises, the consumer still gets a UI-renderable list, but the broken
  row is identifiable.
- A `null` or empty destination is preserved as-is by the mask helper; the mask is applied only to non-empty strings.
  Factor drivers that have no destination (TOTP, backup codes) remain `null` in the summary.
- Email masking uses `explode('@', $destination, 2)`, so an address with multiple `@` characters is split only
  once. The domain portion retains any trailing `@` in the local-part region, which is masked.
- Opaque masking treats anything without an `@` the same way, including phone numbers, passkey labels, and custom
  destination shapes. Four-character-or-shorter inputs are fully masked to avoid leaking a full short credential.
- `FactorSummary` is final, so consumers cannot subclass it to add unvetted fields that would bypass the masking
  contract. Custom projections must be a different class with their own hygiene rules.
- The Eloquent `$hidden` list protects default serialisation but not explicit field access. Code that reads
  `$factor->secret` directly (admin tooling, tests) gets the decrypted plaintext; that is by design for the
  encrypt-at-rest contract, but such code must not send the value over the wire.

## Implementation Anchors

- `src/Factors/FactorSummary.php`: constructor, `fromFactor()`, `jsonSerialize()`, `mask()`, `maskEmail()`,
  `maskOpaque()`.
- `src/Models/Factor.php`: `$casts` (including `'secret' => 'encrypted'`) and `$hidden`.
- `src/Exceptions/MfaRequiredException.php`, `src/Exceptions/MfaExpiredException.php`: exception payloads keyed on
  `FactorSummary[]`.
- `src/Http/Middleware/RequireMfa.php`: `resolveFactorSummaries()` — the single choke point where factors are projected
  through the summary before an exception is thrown.
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
