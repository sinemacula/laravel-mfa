<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Testing\Seams;

use PHPUnit\Framework\Assert;
use SineMacula\Laravel\Mfa\Contracts\ActiveStateResolver;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;

/**
 * What every `ActiveStateResolver` must guarantee, as assertions: an active
 * identity is active, and an inactive one is not.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
final class ActiveStateResolverContract
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * An active identity is active.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\ActiveStateResolver  $resolver
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $active
     * @return void
     */
    public static function assertAnActiveIdentityIsActive(ActiveStateResolver $resolver, MultiFactorAuthenticatable $active): void
    {
        Assert::assertTrue($resolver->isActive($active), 'An active identity must be active.');
    }

    /**
     * An inactive identity is not active.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\ActiveStateResolver  $resolver
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $inactive
     * @return void
     */
    public static function assertAnInactiveIdentityIsNotActive(ActiveStateResolver $resolver, MultiFactorAuthenticatable $inactive): void
    {
        Assert::assertFalse($resolver->isActive($inactive), 'An inactive identity must not be active.');
    }
}
