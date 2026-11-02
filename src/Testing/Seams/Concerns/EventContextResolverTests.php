<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Testing\Seams\Concerns;

use SineMacula\Laravel\Mfa\Contracts\EventContextResolver;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Testing\Seams\EventContextResolverContract;

/**
 * The `EventContextResolver` contract kit: the context is scalar values only.
 *
 * A test case proves its implementation by using this trait and implementing
 * the hooks; each check delegates to `EventContextResolverContract`.
 *
 * @phpstan-require-extends \PHPUnit\Framework\TestCase
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
trait EventContextResolverTests
{
    /**
     * Every value of the context is an integer, a string or `null`.
     *
     * @return void
     */
    public function testEventContextResolverGivesScalarValuesOnly(): void
    {
        EventContextResolverContract::assertGivesScalarValuesOnly($this->eventContextResolver(), $this->eventIdentity());
    }

    /**
     * The resolver under test.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\EventContextResolver
     */
    abstract protected function eventContextResolver(): EventContextResolver;

    /**
     * An identity events are about.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable
     */
    abstract protected function eventIdentity(): MultiFactorAuthenticatable;
}
