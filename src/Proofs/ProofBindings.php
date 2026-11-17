<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Proofs;

use Illuminate\Auth\Events\CurrentDeviceLogout;
use Illuminate\Auth\Events\Login;
use Illuminate\Auth\Events\Logout;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Contracts\Session\Session;
use Illuminate\Queue\Events\JobProcessing;
use SineMacula\Laravel\Mfa\Contracts\PendingCompletion;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Contracts\SessionRevoker;
use SineMacula\Laravel\Mfa\Contracts\StepUp;
use SineMacula\Laravel\Mfa\Support\PackageDefault;

/**
 * Registers the proof service, the default proof seams and the sign-in and job
 * listeners, each built when asked for so no request's session outlives it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ProofBindings
{
    /**
     * @param  \Illuminate\Contracts\Foundation\Application  $app
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public static function register(Application $app): void
    {
        $app->bindIf(
            ProofStore::class,
            static fn (Application $app): ProofStore => new SessionProofStore($app->make(Session::class)),
        );

        $app->bindIf(ProofService::class);
        PackageDefault::bind($app, SessionRevoker::class, GenerationSessionRevoker::class);
        PackageDefault::bind($app, PendingCompletion::class, ProofStoreCompletion::class);
        PackageDefault::bind($app, StepUp::class, ProofStoreCompletion::class);

        $events = $app->make(Dispatcher::class);

        $events->listen(Login::class, BeginSignInOnLogin::class);
        $events->listen(Logout::class, ForgetSignInOnLogout::class);
        $events->listen(CurrentDeviceLogout::class, ForgetSignInOnLogout::class);
        $events->listen(JobProcessing::class, ForgetProofsBeforeJob::class);
    }
}
