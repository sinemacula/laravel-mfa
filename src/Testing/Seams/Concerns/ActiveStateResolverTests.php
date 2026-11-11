<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Testing\Seams\Concerns;

use SineMacula\Laravel\Mfa\Contracts\ActiveStateResolver;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Testing\Seams\ActiveStateResolverContract;

/**
 * The `ActiveStateResolver` contract kit; each check delegates to
 * `ActiveStateResolverContract`.
 *
 * @phpstan-require-extends \PHPUnit\Framework\TestCase
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
trait ActiveStateResolverTests
{
    /**
     * @return void
     */
    public function testActiveStateResolverFindsAnActiveIdentityActive(): void
    {
        ActiveStateResolverContract::assertAnActiveIdentityIsActive($this->activeStateResolver(), $this->activeIdentity());
    }

    /**
     * @return void
     */
    public function testActiveStateResolverFindsAnInactiveIdentityInactive(): void
    {
        ActiveStateResolverContract::assertAnInactiveIdentityIsNotActive($this->activeStateResolver(), $this->inactiveIdentity());
    }

    /**
     * @return \SineMacula\Laravel\Mfa\Contracts\ActiveStateResolver
     */
    abstract protected function activeStateResolver(): ActiveStateResolver;

    /**
     * An identity the layer behind the resolver holds active.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable
     */
    abstract protected function activeIdentity(): MultiFactorAuthenticatable;

    /**
     * An identity the layer behind the resolver holds inactive, such as one
     * suspended.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable
     */
    abstract protected function inactiveIdentity(): MultiFactorAuthenticatable;
}
