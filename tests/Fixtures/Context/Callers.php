<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Context;

use Illuminate\Container\Container;
use SineMacula\Laravel\Mfa\Context\CallerContext;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;

/**
 * Callers built as an application's controller builds them, from the request
 * bound in the container.
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
     * The request's own caller when it is this identity on this application,
     * otherwise the identity on an active session there.
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
