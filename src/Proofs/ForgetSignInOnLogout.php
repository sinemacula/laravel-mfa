<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Proofs;

use Illuminate\Auth\Events\CurrentDeviceLogout;
use Illuminate\Auth\Events\Logout;
use Illuminate\Container\Container;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException;

/**
 * Forgets the identity's sign-in, and every proof of it, on the application the
 * event's guard acts for whenever Laravel's `Logout` or `CurrentDeviceLogout`
 * event fires for an identity that can hold factors, so whoever signs in next
 * on the same session inherits nothing. Its sign-ins on other applications are
 * left alone.
 *
 * An identity whose key cannot name a record holds no proofs, so it is left
 * alone rather than failing the sign-out.
 *
 * The event dispatcher builds a class listener on the application it was booted
 * with and keeps no copy of a request's, so the proof service is resolved from
 * the application serving when the event fires, and acts on its session.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ForgetSignInOnLogout
{
    /**
     * Handle the `Logout` or `CurrentDeviceLogout` event.
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
