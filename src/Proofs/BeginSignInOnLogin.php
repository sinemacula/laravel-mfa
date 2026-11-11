<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Proofs;

use Illuminate\Auth\Events\Login;
use Illuminate\Container\Container;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException;

/**
 * Begins a new sign-in on the guard's application at `Login`, under a fresh
 * random id, so nothing proved there before carries over.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class BeginSignInOnLogin
{
    /**
     * Resolved from the serving application, since the dispatcher keeps the
     * listener it was booted with; an unsupported key holds no proofs.
     *
     * @param  \Illuminate\Auth\Events\Login  $event
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function __invoke(Login $event): void
    {
        if (!$event->user instanceof MultiFactorAuthenticatable) {
            return;
        }

        try {
            $container = Container::getInstance();

            $container->make(ProofService::class)->beginSignIn($event->user, SignInApplication::of($container, $event->guard));
        } catch (UnsupportedIdentifierException) {
            return;
        }
    }
}
