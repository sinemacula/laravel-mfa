# Operating Modes

## Purpose

This note records the three ways the package runs, and the rule that keeps them apart: it works alone, it works with
`sinemacula/laravel-authentication` through adapters, and it works inside `sinemacula/laravel-iam`, and nothing in this
repository can tell which. Any new work keeps all three working.

## Invariants

- This repository never imports `SineMacula\Laravel\Authentication\*`, nor a class of any other sibling. Where the suite
  cooperates, this package declares a seam (see [Seam Contracts](seam-contracts.md)) and an adapter in the application
  or in `laravel-iam` implements it, translating between the two packages' contracts.
- It never detects whether a sibling is installed. Behaviour changes only through container bindings, so there is no
  branch to fall out of step with a mode.
- Every seam has a default that works alone and fails closed. A mode is the set of bindings in force, not a setting.
- Alone, the identity is whatever the guard returns, implementing `Contracts\MultiFactorAuthenticatable`. Each sign-in's
  proofs are in the Laravel session (`Proofs\SessionProofStore`, per device by construction), one sign-in per identity
  and application, begun on Laravel's `Login` event and forgotten on `Logout` or `CurrentDeviceLogout`. It works behind
  the session guard, Sanctum, Passport or any custom guard.
- With `laravel-authentication`, one identity model implements that package's `Identity` and this package's contract.
  Both extend Laravel's `Authenticatable`, so a single class satisfies both. That package is stateless, so a session's
  proofs live with its session record, through a rebound `ProofStore`, and the adapters are constructed in the
  application's service provider or in `laravel-iam`.
- Within `laravel-iam`, the parent provides the `ProofStore` over the authentication session, its own requirement seams
  (`RequirementPolicy`, `IdentityRequirement`, `TenantRequirement`) and freshness gate, and the cross-package listeners
  that audit. The seams here are expressive enough that it has no need to reach around them, and this repository holds
  no knowledge of it.

## Success Path

- Alone: the application configures its blocks and binds its senders, and the defaults do the rest.
- With adapters: a service provider binds the seams it covers, and the flows, which resolve each seam when they run, use
  them from then on. The kits in `Testing\Seams` prove each adapter meets what every implementation must guarantee.
- A value crossing a seam is this package's own (`Proof`, `Requirement`, `VerificationResult`), and the adapter maps it.

## Failure / Edge Cases

- A sibling installed with no adapter bound changes nothing: the defaults still answer, and proofs stay in the Laravel
  session.
- An adapter whose storage is on another connection cannot be atomic with a factor change, and must say so (see
  [Storage and Transactions](storage-and-transactions.md)).
- A stateless guard with the default store has no session to keep proofs in, so it needs a rebound `ProofStore` even
  with no sibling installed.

## Implementation Anchors

- `src/Contracts/`: the seams; `src/*/*Bindings.php`: their defaults.
- `src/Proofs/SessionProofStore.php`, `src/Proofs/BeginSignInOnLogin.php`, `src/Proofs/ForgetSignInOnLogout.php`.
- `src/Testing/Seams/`: the contract kits an adapter uses.

## Authoritative Tests

- `tests/Integration/MultiAuthStackTest.php` `testSanctumGuardSeesIdentityAndFactors`
- `tests/Integration/PolymorphicIdentityTest.php`
- `tests/Feature/Proofs/SignInProofsTest.php`
- `tests/Unit/Testing/Seams/`

## Change Triggers

- Anything that would import a sibling's class, or detect whether one is installed.
- A flow that cannot be served by a seam's default working alone.
- A new mode of running, or a change in which seams a mode rebinds.
