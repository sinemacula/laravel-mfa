# Combination Policy

## Purpose

This note records how the default combination policy decides whether a factor may follow a session's first factor,
and how it classifies a session's proofs: whether they are an accepted additional verification, multifactor
authentication, the NIST SP 800-63B-4 level they support, whether they are phishing-resistant or restricted, the `amr`
values they report, and which parts of a requirement they meet within each part's maximum age.

## Invariants

- Every answer comes from the channel each proof travelled on, which the driver fixes, and from the properties the
  proof observed. Nothing is inferred from a factor type's name or from configuration, and nothing not observed is
  reported.
- A factor is independent of the first factor unless the two share a channel: the same kind with the same destination
  or credential, or the same kind where either names none. Email addresses are compared without regard to case; phone
  numbers and credentials exactly.
- Only a first factor, or a reauthentication with it, on a known channel accepts a factor, and only a channel that can
  carry a factor (not a password or an unknown one) is accepted. A recovery code has no channel and follows any known
  first factor.
- `evaluate()` needs exactly one first factor among the proofs, on a known channel. With none, with more than one, or
  with an unknown one, nothing is accepted, nothing is multifactor, the level is unclassified, no `amr` value is
  reported and every part of the requirement is unmet.
- A proof bound to another identity (type or key) or another application than the first factor counts for nothing.
- Each proof is classified as an authenticator (`Assurance\Authenticator`): a password is something known; an SMS
  code, a TOTP code, a recovery code and a passkey are something had; a passkey whose assertion observed user
  verification is a multi-factor authenticator; an email code and an external provider's first factor are neither and
  establish no level. Only an SMS code is restricted.
- The proofs form combinations (`Assurance\Combination`): the first factor alone, each reauthentication with it alone
  on a known channel, and the first factor followed by each further proof it accepts. A combination is multifactor when
  it holds a multi-factor authenticator, or something known with something had; it then supports AAL2, and otherwise
  AAL1 when it holds anything known or had, or no level. It is restricted when it holds a restricted authenticator and
  no multi-factor authenticator.
- The session is accepted when any further proof is accepted, multifactor when any combination is, phishing-resistant
  when any combination holds a proof that observed phishing resistance, and at the highest level any combination
  reaches. It is restricted only when that level is a level and every combination reaching it is restricted.
- The level is never AAL3.
- `amr` holds each counting proof's method value (`pwd`, `sms`, `otp` for TOTP, email and recovery codes, `pop` for a
  passkey), `user` for observed user presence, `hwk` or `swk` for observed key protection, each once in the order first
  reported, the first factor's first; then `mfa` when multifactor, or `mca` when accepted and not multifactor. An
  external provider's first factor adds no value.
- A requirement part is met when one combination provides it and the proof that completes that combination (the
  further proof, or the lone first factor or reauthentication) is within the part's maximum age at the current time:
  `additional_verification` by an accepted or multifactor combination, `multifactor` by a multifactor one,
  `minimum_level` by one at or above the level, and `phishing_resistance` by a phishing-resistant one. A maximum age is
  inclusive, and a proof dated after the current time is within none.

## Success Path

- The provider registers `Assurance\AssuranceBindings`, which binds `Contracts\CombinationPolicy` to
  `Assurance\DefaultCombinationPolicy` as a singleton. The policy holds no state.
- Before offering or verifying a factor on a session, a flow asks `accepts()` with the session's first-factor proof and
  the factor's channel; a refused factor is neither offered nor verified.
- After a proof, a flow asks `evaluate()` with the outstanding requirement and the session's proofs, and acts on the
  `Evaluation`: its answers, its `amr` values and the parts met and unmet.

## Failure / Edge Cases

- A phone code followed by an SMS code to the same phone, or an email code followed by one to the same address, is
  refused by `accepts()`; were such a proof passed to `evaluate()`, it would count for nothing, leaving the first
  factor's own classification.
- A first factor of a channel kind that names no destination or credential refuses every factor of that kind, as
  independence cannot be shown.
- A passkey sign-in with observed user verification meets `additional_verification` and `multifactor` on its own, but
  not once it is older than a part's maximum age; the evaluation still reports it multifactor at AAL2.
- A fresh reauthentication with the first factor meets a fresh `minimum_level` it reaches on its own, never a fresh
  `additional_verification`: it is not an additional factor.
- A fresh further proof after an old first factor meets a fresh part, as a step-up does.
- An email code after an external provider is accepted, at no level, and reports `otp` and `mca`.
- A rebound policy is checked by `Evaluation` itself, which refuses a part met that its own answers rule out, `mfa`
  without multifactor and `mca` without an accepted combination that is not multifactor.

## Implementation Anchors

- `src/Assurance/DefaultCombinationPolicy.php`: `accepts()`, `evaluate()`, `shareChannel()`, `firstFactor()`,
  `combinationOf()`, `restrictedAt()`, `amr()`, `isMet()`.
- `src/Assurance/Authenticator.php`: the classification of one proof and its `amr` values.
- `src/Assurance/Combination.php`: the level, multifactor answer, restriction and maximum age of one combination.
- `src/Assurance/AssuranceBindings.php`: the default binding.
- `src/Contracts/CombinationPolicy.php`: the contract.

## Authoritative Tests

- `tests/Unit/Assurance/DefaultCombinationPolicyTest.php`
  `testAcceptsAFactorOnlyOnAnIndependentChannel`
- `tests/Unit/Assurance/DefaultCombinationPolicyTest.php`
  `testClassifiesTheCombination`
- `tests/Unit/Assurance/DefaultCombinationPolicyTest.php`
  `testAnOldMultiFactorFirstFactorIsNotFreshForAnOperation`
- `tests/Unit/Assurance/DefaultCombinationPolicyTest.php`
  `testAFreshFirstFactorNeverStandsInForAnAdditionalFactor`
- `tests/Unit/Assurance/DefaultCombinationPolicyTest.php`
  `testJudgesEachPartOfTheRequirement`
- `tests/Unit/Assurance/DefaultCombinationPolicyTest.php`
  `testAProofBoundElsewhereCountsForNothing`
- `tests/Unit/Assurance/DefaultCombinationPolicyTest.php`
  `testNeverReportsAal3`
- `tests/Unit/Assurance/AuthenticatorTest.php`
  `testClassifiesTheProof`
- `tests/Unit/Assurance/CombinationTest.php`
  `testIsWithinAMaximumAge`
- `tests/Unit/Assurance/AssuranceBindingsTest.php`
  `testBindsTheDefaultPolicyAsASingleton`

## Change Triggers

Update this note when any of the following change:

- what makes two channels shared, or which first factors accept a factor
- how a proof is classified as an authenticator, or which authenticators are restricted
- how combinations are formed, or how a combination's level, multifactor answer or restriction is reached
- the `amr` values reported, or their order
- how a requirement part and its maximum age are judged
- the default binding of `CombinationPolicy`
