<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Proofs;

use Illuminate\Auth\Events\CurrentDeviceLogout;
use Illuminate\Auth\Events\Logout;
use Illuminate\Container\Container;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException;

/**
 * Forgets the sign-in and its proofs on the guard's application at sign-out, so
 * whoever signs in next on the session inherits nothing.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ForgetSignInOnLogout
{
    /**
     * Resolved from the serving application, since the dispatcher keeps the
     * listener it was booted with; an unsupported key holds no proofs.
     *
     * @param  \Illuminate\Auth\Events\CurrentDeviceLogout|\Illuminate\Auth\Events\Logout  $event
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function __invoke(CurrentDeviceLogout|Logout $event): void
    {
        if (!$event->user instanceof MultiFactorAuthenticatable) {
            return;
        }

        try {
            $container = Container::getInstance();

            $container->make(ProofService::class)->endSignIn($event->user, SignInApplication::of($container, $event->guard));
        } catch (UnsupportedIdentifierException) {
            return;
        }
    }
}
