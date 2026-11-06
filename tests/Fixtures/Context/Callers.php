<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Context;

use Illuminate\Container\Container;
use SineMacula\Laravel\Mfa\Context\CallerContext;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;

/**
 * The caller of the request a test is serving, as an application's controller
 * builds it: `CallerContext::fromRequest()` over the request bound in the
 * container, so the guard the test signed in on and a pending session it put on
 * the request are read the way a real request's are.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class Callers
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * The caller of the request being served, through the guard named or the
     * default one.
     *
     * @param  ?string  $guard
     * @return \SineMacula\Laravel\Mfa\Context\CallerContext
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public static function current(?string $guard = null): CallerContext
    {
        $container = Container::getInstance();

        return CallerContext::fromRequest($container->make('request'), $guard, $container);
    }

    /**
     * The caller an authentication layer builds for the identity on the
     * application: the request's own, pending or active, when it is that
     * identity on that application, and otherwise the identity on an active
     * session there.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @return \SineMacula\Laravel\Mfa\Context\CallerContext
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public static function of(MultiFactorAuthenticatable $identity, string $application): CallerContext
    {
        $current = self::current();
        $same    = $current->identity !== null
            && $current->application                      === $application
            && ProofOwner::of($current->identity)->slot() === ProofOwner::of($identity)->slot();

        return $same ? $current : CallerContext::forIdentity($identity, $application, $current->client);
    }
}
