<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Proofs;

use Illuminate\Auth\Events\CurrentDeviceLogout;
use Illuminate\Auth\Events\Login;
use Illuminate\Auth\Events\Logout;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Contracts\Session\Session;
use SineMacula\Laravel\Mfa\Contracts\PendingCompletion;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Contracts\SessionRevoker;
use SineMacula\Laravel\Mfa\Contracts\StepUp;

/**
 * Registers the proof service, the default `ProofStore`, which keeps each
 * sign-in's proofs in the Laravel session, the default `SessionRevoker`, which
 * advances the identity's verification generation, the default
 * `PendingCompletion` and `StepUp`, which record a verified proof in the store
 * (`ProofStoreCompletion`), and the listeners that begin a sign-in on Laravel's
 * `Login` event and forget it on `Logout` and `CurrentDeviceLogout`.
 *
 * Like every package service, each is built when it is asked for, the store
 * from the session of the request at hand, so nothing the container keeps holds
 * one request's session into the next. An application on a stateless guard
 * rebinds the `ProofStore` contract in its own service provider.
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
     * Register the proof service, the default proof store, session revoker,
     * pending completion and step-up, and the sign-in listeners.
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

        $app->bind(ProofService::class);
        $app->bind(SessionRevoker::class, GenerationSessionRevoker::class);
        $app->bind(PendingCompletion::class, ProofStoreCompletion::class);
        $app->bind(StepUp::class, ProofStoreCompletion::class);

        $events = $app->make(Dispatcher::class);

        $events->listen(Login::class, BeginSignInOnLogin::class);
        $events->listen(Logout::class, ForgetSignInOnLogout::class);
        $events->listen(CurrentDeviceLogout::class, ForgetSignInOnLogout::class);
    }
}
