<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Proofs;

use Illuminate\Contracts\Foundation\Application;
use Illuminate\Contracts\Session\Session;
use SineMacula\Laravel\Mfa\Contracts\MfaVerificationStore;

/**
 * Registers the proof service and the default `MfaVerificationStore`, which
 * keeps verification state in the session. Consumers running a stateless stack
 * (JWT, personal access tokens) rebind the `MfaVerificationStore` contract in
 * their own service provider.
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
     * Register the proof service and the default verification store.
     *
     * @param  \Illuminate\Contracts\Foundation\Application  $app
     * @return void
     */
    public static function register(Application $app): void
    {
        $app->singleton(
            MfaVerificationStore::class,
            static fn (Application $app): MfaVerificationStore => new SessionMfaVerificationStore(
                $app->make(Session::class),
            ),
        );

        $app->singleton(ProofService::class);
    }
}
