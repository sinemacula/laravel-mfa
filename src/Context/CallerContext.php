<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Context;

use Illuminate\Container\Container;
use Illuminate\Contracts\Container\Container as ContainerContract;
use Illuminate\Http\Request;
use SineMacula\Laravel\Mfa\Contracts\ApplicationResolver;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\PendingSessionResolver;

/**
 * Who an action is served to, as plain values: the identity the caller
 * authenticated as, or the pending session it holds, the application it acts
 * on, and its client. Every self-service action takes one first.
 *
 * It is trusted input from the application's own code, not proof of who the
 * caller is: building one authenticates nobody. The action decides whether it
 * serves the caller (a pending session only what its credential allows, and
 * only a person), and re-checks under the identity's lock that the pending
 * credential still validates, or that the store's current sign-in is still the
 * one the action began on. The sign-in is never carried here: it is read from
 * the proof store for the identity and the application.
 *
 * `fromRequest()` is the one place it is read from a request. With no request,
 * as in a queued job or a console command, build one with `forIdentity()`,
 * `forPending()` or `nobody()`.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class CallerContext
{
    /**
     * Constructor.
     *
     * @param  ?\SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  ?\SineMacula\Laravel\Mfa\Context\PendingContext  $pending
     * @param  string  $application
     * @param  \SineMacula\Laravel\Mfa\Context\ClientContext  $client
     *
     * @throws \InvalidArgumentException
     */
    private function __construct(

        /** The identity the caller authenticated as, or the pending session's, or `null` when it is nobody. */
        public ?MultiFactorAuthenticatable $identity,

        /** The pending session the caller holds, or `null` for an active one. */
        public ?PendingContext $pending,

        /** The application the caller acts on. */
        public string $application,

        /** The caller's client. */
        public ClientContext $client,
    ) {
        if (trim($application) === '') {
            throw new \InvalidArgumentException('The application of a caller must not be blank.');
        }
    }

    /**
     * An identity on an active session of the application.
     *
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
     * A pending session, on its own identity and application.
     *
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
     * Nobody, on the application: every action that serves a caller serves
     * nothing.
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
     * The caller of the request, through the guard named, or the default one.
     *
     * The bound `PendingSessionResolver` is asked first: a pending session it
     * reads is the caller, and an invalid pending credential it throws for is
     * not caught, so the request is refused rather than served as the guard's
     * user. Otherwise the caller is the user the named guard authenticated for
     * the request, when it is one this package serves, or nobody. The
     * application is the one a bound `ApplicationResolver` names for the
     * request, or else the guard's name.
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
        $application = $container->bound(ApplicationResolver::class) ? $container->make(ApplicationResolver::class)->resolve($request) : $guard;
        $identity    = $container->make('auth')->guard($guard)->user();

        return $identity instanceof MultiFactorAuthenticatable
            ? self::forIdentity($identity, $application, $client)
            : self::nobody($application, $client);
    }
}
