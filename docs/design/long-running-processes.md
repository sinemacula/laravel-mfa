# Long-Running Processes

## Purpose

This note describes how the package stays correct when one application serves many requests (Laravel Octane) or runs
many jobs (a queue worker): what the container keeps, how the listeners reach the request at hand, what is proven, and
what is not.

## Invariants

- Every package service and default seam is bound with `bind()`, so the container keeps no instance of any of them,
  whichever application resolved it and when. Only `mfa` is shared: a registry that declares no property of its own and
  resolves from the current application on every call.
- `scoped()` is deliberately not used. `Container::forgetScopedInstances()` forgets by abstract, so an application's
  `instance()` over a seam, or `Testing\FakeSenderBinding`, would vanish after the first request and the fail-closed
  default would return at run time. An application's own `instance()` or `singleton()` still wins over `bind()`.
- `bind()` stops the container keeping an instance, not an application singleton retaining one: consumers resolve these
  services for each operation, and do not hold them across requests.
- The manager inherits `Manager`'s container and configuration fields, set when it was built. Its operations do not use
  them: each goes to `Container::getInstance()`.
- `Proofs\BeginSignInOnLogin` and `Proofs\ForgetSignInOnLogout` take no constructor dependency, and resolve the proof
  service from `Container::getInstance()` when the event fires, as `Proofs\GuardHooks` does. The event dispatcher builds
  a class listener on the application it was booted with, so a dependency in the constructor would reach the booted
  container's proof store, whatever a request's sandbox bound. Binding the service with `bind()` does not fix that: a
  transient built on the wrong container is still on it.
- The package declares no static property and no static local variable. `Database\WriteConnection::during()` restores
  the connection's read mode when its callback returns or throws, and `Database\StorageTransaction` forgets the work a
  failed commit left waiting.
- The package owns no guard and resets none. `Support\CurrentIdentity` reads `Auth::user()`, and Laravel's queue worker
  does not forget guards between jobs, so a job acting for a person sets its own identity, and an application on plain
  Laravel guards clears them with `Queue::before()` (see [Operations](../guides/operations.md#queue-workers)). A
  listener of the package's own calling `Auth::forgetGuards()` was rejected: it would reach into guards the package does
  not own.
- The default proof store keeps its records in the Laravel session, and Laravel's worker does not reset the session
  between jobs: `session.store` is a singleton, and `$resetScope` leaves it alone. So the records live in the worker's
  session until they are cleared, and a job for the same person would read an earlier job's proofs. The session is the
  application's as the guards are, so the same `Queue::before()` flushes it, for jobs that are not `sync`.
- No cache is used anywhere, so nothing depends on a cache's contents or its being up.

## Success Path

- A worker boots and may resolve services (`octane.warm`, an early `Mfa::extend()`, the boot check). Nothing it resolves
  is kept, but `mfa`, which costs only a configuration check and driver registration.
- Octane clones the application into a sandbox for each request. Each service is built there, reads that sandbox's
  configuration and seams, and acts on its session, its guards and its dispatcher, and the sandbox goes with the
  request.
- A queued job runs on the worker's one application. Each service is built for the job; `$resetScope` forgets scoped
  instances between jobs, and leaves an installed fake sender alone.

## Failure / Edge Cases

- A pin on the write connection whose callback throws is released, so the next request reads as configured.
- A commit that fails leaves nothing waiting for the next request's commit, on every Laravel version the package
  supports, in a transaction the package opened. In a transaction the caller opened, that commit is the caller's: on
  Laravel 12 what waited for it stays queued until the connection's next commit unless the caller forgets it.
- A `sync` job runs inside the request that dispatched it, so its guards are that request's.

## What Is and Is Not Proven

- Consecutive requests are served through Octane's real `Worker` and its listeners, with its server faked, and through a
  real session on files, so what a person proved lasts between their requests and nothing else does.
- Jobs run through a real `Worker::daemon()`, because `$resetScope` runs there and not in `runNextJob()`.
- No test runs Swoole, RoadRunner or FrankenPHP, and no process is restarted. The static property and variable rules
  read what is declared, so they keep holding for what is added later, and they say nothing of a static a dependency
  keeps.

## Implementation Anchors

- `src/MfaServiceProvider.php`: `registerManager()`; every `*Bindings` class's `register()`.
- `src/Proofs/BeginSignInOnLogin.php`, `src/Proofs/ForgetSignInOnLogout.php`.
- `src/MfaManager.php`: `service()`, `driver()`.

## Authoritative Tests

- `tests/Integration/Octane/ConsecutiveRequestsTest.php`
- `tests/Integration/Process/QueueWorkerStateTest.php`
- `tests/Unit/LongRunningSafetyTest.php`
- `tests/Unit/MfaManagerLongRunningTest.php`
- `tests/Integration/CacheIndependenceTest.php`

## Change Triggers

- A new binding, a new listener registered by class, a new static, or a use of the cache.
- A change to Octane's or Laravel's worker lifecycle that the tests above rely on.
