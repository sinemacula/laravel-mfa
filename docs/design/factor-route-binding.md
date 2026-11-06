# Factor Route Binding

## Purpose

This note records how a route parameter of the factor model binds: only within the caller's identity, from whichever
credential the route uses, through the model's own lookup. It also records what the binding does not reach.

## Invariants

- `Concerns\ResolvesFactorRouteBinding` overrides `resolveRouteBinding()` and `resolveSoftDeletableRouteBinding()`, each
  handing `parent::...($value, $field)` as a closure to `Factors\FactorRouteBinding`, resolved through
  `Container::getInstance()`. The lookup is the parent's, so a custom key, `withTrashed()` and a base model's own
  binding (a hashid decoder, say) keep working.
- The shipped `Models\Factor` uses the trait, so an ordinary implicit binding of it enforces ownership with nothing
  else to do. An application's own model opts in beside `Concerns\ActsAsFactor`.
- `FactorRouteBinding::resolve()`:
  1. resolves the caller (`CallerContextResolver::forFactorBinding()`); none, or one whose key is neither a string nor
     an integer, is `null`, with no query;
  2. runs the lookup under `Database\WriteConnection::during()`, so a replica cannot lag behind a removal, catching only
     `ModelNotFoundException`, which Eloquent throws for a malformed unique id, as `null`;
  3. keeps what it found only when it is an instance of the model and `Support\FactorOwnerColumns::owns()` says the
     caller owns it, exactly: a case-insensitive collation cannot match another owner, and a model's remapped owner
     columns are read from its `authenticatable` relation. Anything else is `null`.
- `forFactorBinding()` reads the pending context once:
  - a pending session is served only when its credential allows one of the actions that name an existing factor
    (`mfa.list_factors`, `mfa.send_code`, `mfa.verify`), so a credential allowing only bootstrap enrolment binds
    nothing, and the guard's user never stands in;
  - with no pending session, the guard's identity is served;
  - either way, only a person, as the bound `SubjectTypeResolver` says.
- The binding is an ownership rule, not permission to run the route. A list-only credential binds on a verify URL, and
  `Mfa::verify()` then refuses it. Visibility matches `Mfa::factor()`: pending and disabled factors and those enrolled
  through another application bind, and each helper enforces its own rules. `isMfaActive()` is not read, as `factors()`
  does not read it.
- `WriteConnection::during()` sets `useWriteConnectionWhenReading()` on the model's connection and restores the earlier
  mode in `finally`, reading the protected flag through a bound closure, as Laravel offers no getter. Eager loads on
  that connection read the writer too.

## Success Path

- `GET /factors/{factor}` behind `auth`: the signed-in person's factor.
- `POST /sign-in/factors/{factor}/verify` with a pending credential the bound `PendingSessionResolver` validates: the
  pending session's own factor, `Mfa::verify()` then asking for `mfa.verify` itself.
- A helper takes the factor's id, not the model: `Mfa::removeFactor($caller, $factor->getFactorIdentifier())`.
  `getRouteKey()` is not the same value under a custom key.

## Failure / Edge Cases

- A database failure propagates: a failing query is a server error, never a missing factor.
- A pending credential the resolver refuses to validate propagates from the resolver, which reports it; it is not a
  `404`.
- The caller must be established before `SubstituteBindings` runs, as the binding reads it there. Laravel's middleware
  priority orders `auth` ahead of it. Any other middleware that establishes the credential must be placed ahead of it in
  the priority list, or the factor binds to nobody and answers `404`, or is held to the guard's user rather than the
  credential the route goes on to use. Either fails closed.
- A custom key must be unique across identities. With `{factor:type}` the first row found may be another person's, and
  the binding misses, failing closed. A lookup within one identity goes through `Mfa::factors()`.
- A scoped child binding through a parent model (`/users/{user}/factors/{factor}`) is the parent's own lookup and never
  reaches the trait, so such a route must scope its parent to the caller itself. `Route::bind()` is the application's
  own, and is the way to bind other people's factors; `unlockFactor()` and `resetIdentity()` take the identity and a raw
  id, so an administrator needs no bound model.
- An eager load on another connection is not pinned to its writer, and is not a security input.
- A model passed to a helper finds nothing, since a helper looks up an id: `Mfa::removeFactor($caller, $factor)` answers
  `not_found`.

## Rejected

- Overriding `resolveRouteBindingQuery()` to scope the query would make non-unique keys work and catch scoped child
  bindings, but `HasUniqueStringIds` (`HasUlids`, `HasUuids`) declares the same method, so the trait would collide on
  the shipped model and on any ULID or UUID model. `insteadof` can compose them, which is too much to ask of every
  adopter.
- Calling `$this->resolveRouteBindingQuery(...)->first()` rather than the parent would skip a base model's own
  `resolveRouteBinding()`.
- Overriding the two child binding methods as well: a factor has no children of its own.

## Implementation Anchors

- `src/Concerns/ResolvesFactorRouteBinding.php`, `src/Factors/FactorRouteBinding.php`.
- `src/Context/CallerContextResolver.php`: `forFactorBinding()`.
- `src/Database/WriteConnection.php`: `during()`.
- `src/Support/FactorOwnerColumns.php`: `owns()`.

## Authoritative Tests

- `tests/Unit/Concerns/ResolvesFactorRouteBindingTest.php`
  `testAnotherIdentitysFactorMisses`
- `tests/Unit/Concerns/ResolvesFactorRouteBindingTest.php`
  `testNoCallerMissesWithNoQuery`
- `tests/Unit/Concerns/ResolvesFactorRouteBindingTest.php`
  `testADuplicateCustomKeyFailsClosed`
- `tests/Unit/Concerns/ResolvesFactorRouteBindingTest.php`
  `testABaseModelsOwnBindingIsTheLookup`
- `tests/Unit/Concerns/ResolvesFactorRouteBindingTest.php`
  `testAnOwnerDifferingOnlyInCaseMisses`
- `tests/Feature/Factors/FactorRouteBindingTest.php`
  `testAPendingCredentialBindsPerItsActions`
- `tests/Feature/Factors/FactorRouteBindingTest.php`
  `testAListOnlyCredentialBindsAndVerifyStillRefuses`
- `tests/Feature/Factors/FactorRouteBindingTest.php`
  `testAScopedChildBindingIsTheParentsOwnLookup`
- `tests/Integration/Database/WriteConnectionReadTest.php`
  `testAFactorNotYetOnTheReaderStillBinds`

## Change Triggers

Update this note when any of the following change:

- which actions of a pending credential serve a binding
- what the binding reads from the write connection
- whether the shipped model uses the trait
- which of Eloquent's binding methods the trait overrides
