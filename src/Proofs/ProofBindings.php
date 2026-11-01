<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Proofs;

use Illuminate\Auth\Events\CurrentDeviceLogout;
use Illuminate\Auth\Events\Login;
use Illuminate\Auth\Events\Logout;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Contracts\Session\Session;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;

/**
 * Registers the proof service, the default `ProofStore`, which keeps each
 * sign-in's proofs in the Laravel session, and the listeners that begin a
 * sign-in on Laravel's `Login` event and forget it on `Logout` and
 * `CurrentDeviceLogout`.
 *
 * The store is built on every resolution, from the session of the request at
 * hand, so no singleton holds one request's session into the next. An
 * application on a stateless guard rebinds the `ProofStore` contract in its own
 * service provider.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ProofBindings
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Register the proof service, the default proof store and the sign-in
     * listeners.
     *
     * @param  \Illuminate\Contracts\Foundation\Application  $app
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public static function register(Application $app): void
    {
        $app->bind(
            ProofStore::class,
            static fn (Application $app): ProofStore => new SessionProofStore($app->make(Session::class)),
        );

        $app->singleton(ProofService::class);

        $events = $app->make(Dispatcher::class);

        $events->listen(Login::class, BeginSignInOnLogin::class);
        $events->listen(Logout::class, ForgetSignInOnLogout::class);
        $events->listen(CurrentDeviceLogout::class, ForgetSignInOnLogout::class);
    }
}
