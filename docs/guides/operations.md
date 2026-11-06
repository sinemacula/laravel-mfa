# Operations

Running the package in production: what a long-running process keeps between requests and jobs, where its reads go, what
happens when the database fails, and what it asks of the cache. Every class name below is relative to
`SineMacula\Laravel\Mfa`.

## Octane

Octane serves each request in a sandbox: a copy of the application the worker booted, with a configuration of its own
and the request bound. Every package service and default seam is built when it is asked for, so `Mfa::verify()` and the
other helpers act on the sandbox: its session, its guards, its configuration and whatever it binds. A value one request
configures, a seam it binds and a dispatcher it swaps in reach that request alone. The sign-in listeners do the same:
`Login`, `Logout` and `CurrentDeviceLogout` reach the proof store of the request serving, though they are registered
once.

The `mfa` manager stays shared, and is rebuilt per sandbox unless it was resolved at boot, by `octane.warm` or an early
`Mfa::extend()`. Warming it costs only a configuration check and driver registration, as it declares no property of its
own and resolves everything else from the application serving. Warming any other package service has no effect: none is
kept.

An application's own `singleton()` over one of the package's contracts is the application's to keep safe. Bind it with
`bind()`, or read what it needs from the container on each call, and hold no request state on it.

## Queue workers

A worker runs many jobs in one application, and does not forget guards between them. The helpers read no guard and the
package owns none, so it resets none. A job acting for a person names them in the caller it builds:

```php
use SineMacula\Laravel\Mfa\Context\CallerContext;
use SineMacula\Laravel\Mfa\Facades\Mfa;

public function handle(): void
{
    Mfa::factors(CallerContext::forIdentity($this->person, 'web'));
}
```

An application on plain Laravel guards still clears them before each job, so its own code in a job never acts as the
last job's person. It clears the session too: the default proof store keeps its records
in the session, and a worker's session lives in memory for as long as the worker does, so without this a job would read
the proofs an earlier job made for the same person. Leave `sync` jobs out: they run inside the request that dispatched
them, and clearing its guards and its session would sign that request out.

```php
use Illuminate\Queue\Events\JobProcessing;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Queue;
use Illuminate\Support\Facades\Session;

Queue::before(static function (JobProcessing $event): void {
    if ($event->connectionName !== 'sync') {
        Auth::forgetGuards();
        Session::flush();
    }
});
```

Paired with the authentication package, its own reset on `JobProcessing` covers its guards only, so a plain Laravel
guard in the same application still needs the above.

A fake sender installed at boot, `Testing\FakeSmsSender::fake()` or `Testing\FakeEmailSender::fake()`, survives the
worker's reset between jobs, as the package binds nothing with `scoped()`.

## Read replicas

Everything a verification, a lockout or an ownership check decides on is read from the storage connection's write host,
even when the connection has `read` and `write` hosts: factors, attempts, lockouts, accepted TOTP steps, delivered
codes, recovery codes, passkey associations and the verification generation. A replica behind any of them cannot pass a
replay, miss a lockout or let a removed factor count. A proof store of your own that reads a database must do the same,
as must any read a seam of yours makes that decides who may do what.

## When the database fails

A failing query is a server error, never a wrong code, a missing factor or "not set up": a failover neither locks people
out nor lets them skip a factor. Each helper throws the `QueryException`, or Laravel's `DeadlockException` for a
concurrency failure inside a nested transaction, and Laravel answers either with a 500. A transaction runs once and is
not retried, as running it again would run the driver again and could deliver a second code, so a deadlock is a 500 too,
for the client to retry.

The one database error answered as a refusal is a passkey's credential already being associated. A registration that
meets a unique violation looks the credential up with a locking read: finding it answers `credential_associated`, and
finding nothing is a server error like any other. Finding the credential establishes the conflict, not which index
fired.

A sender that fails is `Exceptions\CodeDeliveryFailedException`, which the package does not map to a response, so it is
a 500 too.

Nothing a failed query was given stays in its exception: see [Secrets](secrets.md#failed-queries).

## Database privileges

Migrations are published and run by your migration user (see [Installation](installation.md#publishing-and-migrating)).
At run time the package needs only `SELECT`, `INSERT`, `UPDATE` and `DELETE`, and it makes no schema change.

## The cache

Nothing the package does uses the cache. Attempts, lockouts, replay state and codes live in the database, so a cache
that is down or answers falsely changes nothing, and no secret is ever in one.
