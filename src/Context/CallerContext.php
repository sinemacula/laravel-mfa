<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Context;

use Illuminate\Container\Container;
use Illuminate\Contracts\Container\Container as ContainerContract;
use Illuminate\Http\Request;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\PendingSessionResolver;

/**
 * Who an action is served to. Trusted input from the application's own code:
 * building one authenticates nobody, and each action re-checks the caller under
 * the identity's lock. The sign-in is read from the proof store, never carried
 * here.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class CallerContext
{
    /**
     * @param  ?\SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  ?\SineMacula\Laravel\Mfa\Context\PendingContext  $pending
     * @param  string  $application
     * @param  \SineMacula\Laravel\Mfa\Context\ClientContext  $client
     *
     * @throws \InvalidArgumentException
     */
    private function __construct(

        /** `null` for nobody. */
        public ?MultiFactorAuthenticatable $identity,

        /** `null` on an active session. */
        public ?PendingContext $pending,

        /** The application acted on. */
        public string $application,

        /** The caller's client. */
        public ClientContext $client,
    ) {
        if (trim($application) === '') {
            throw new \InvalidArgumentException('The application of a caller must not be blank.');
        }
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @param  ?\SineMacula\Laravel\Mfa\Context\ClientContext  $client
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function forIdentity(MultiFactorAuthenticatable $identity, string $application, ?ClientContext $client = null): self
    {
        return new self($identity, null, $application, $client ?? ClientContext::unknown());
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Context\PendingContext  $pending
     * @param  ?\SineMacula\Laravel\Mfa\Context\ClientContext  $client
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function forPending(PendingContext $pending, ?ClientContext $client = null): self
    {
        return new self($pending->identity, $pending, $pending->application, $client ?? ClientContext::unknown());
    }

    /**
     * Every action that serves a caller serves nothing.
     *
     * @param  string  $application
     * @param  ?\SineMacula\Laravel\Mfa\Context\ClientContext  $client
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function nobody(string $application, ?ClientContext $client = null): self
    {
        return new self(null, null, $application, $client ?? ClientContext::unknown());
    }

    /**
     * A pending session wins over the guard's user, and an invalid pending
     * credential throws so the request is refused rather than served as that
     * user.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  ?string  $guard
     * @param  ?\Illuminate\Contracts\Container\Container  $container
     * @return self
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     */
    public static function fromRequest(Request $request, ?string $guard = null, ?ContainerContract $container = null): self
    {
        $container ??= Container::getInstance();
        $client  = ClientContext::fromRequest($request);
        $pending = $container->make(PendingSessionResolver::class)->fromRequest($request);

        if ($pending !== null) {
            return self::forPending($pending, $client);
        }

        $guard ??= $container->make('auth')->getDefaultDriver();
        $application = RequestApplication::of($container, $request, $guard);
        $identity    = $container->make('auth')->guard($guard)->user();

        return $identity instanceof MultiFactorAuthenticatable
            ? self::forIdentity($identity, $application, $client)
            : self::nobody($application, $client);
    }
}
