<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Testing\Seams\Concerns;

use Illuminate\Http\Request;
use SineMacula\Laravel\Mfa\Contracts\GuardApplicationResolver;
use SineMacula\Laravel\Mfa\Testing\Seams\GuardApplicationResolverContract;

/**
 * The `GuardApplicationResolver` contract kit; use it beside
 * `ApplicationResolverTests`, which proves the form without a guard.
 *
 * @phpstan-require-extends \PHPUnit\Framework\TestCase
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
trait GuardApplicationResolverTests
{
    /**
     * @return void
     */
    public function testGuardApplicationResolverNamesOneApplicationThroughTheGuard(): void
    {
        GuardApplicationResolverContract::assertNamesOneApplicationThroughTheGuard($this->guardApplicationResolver(), $this->guardApplicationRequest(), $this->applicationGuard());
    }

    /**
     * @return \SineMacula\Laravel\Mfa\Contracts\GuardApplicationResolver
     */
    abstract protected function guardApplicationResolver(): GuardApplicationResolver;

    /**
     * @return \Illuminate\Http\Request
     */
    abstract protected function guardApplicationRequest(): Request;

    /**
     * Such as one other than the default.
     *
     * @return string
     */
    abstract protected function applicationGuard(): string;
}
