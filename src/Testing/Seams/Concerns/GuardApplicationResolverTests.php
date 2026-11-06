<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Testing\Seams\Concerns;

use Illuminate\Http\Request;
use SineMacula\Laravel\Mfa\Contracts\GuardApplicationResolver;
use SineMacula\Laravel\Mfa\Testing\Seams\GuardApplicationResolverContract;

/**
 * The `GuardApplicationResolver` contract kit: a request names one application
 * through a guard, the same way each time. A resolver that implements the guard
 * aware form uses this trait beside `ApplicationResolverTests`, which proves
 * the form without a guard.
 *
 * A test case proves its implementation by using this trait and implementing
 * the hooks; each check delegates to `GuardApplicationResolverContract`.
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
     * The request's application through the guard is named, the same way each
     * time.
     *
     * @return void
     */
    public function testGuardApplicationResolverNamesOneApplicationThroughTheGuard(): void
    {
        GuardApplicationResolverContract::assertNamesOneApplicationThroughTheGuard($this->guardApplicationResolver(), $this->guardApplicationRequest(), $this->applicationGuard());
    }

    /**
     * The resolver under test.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\GuardApplicationResolver
     */
    abstract protected function guardApplicationResolver(): GuardApplicationResolver;

    /**
     * A request for an application.
     *
     * @return \Illuminate\Http\Request
     */
    abstract protected function guardApplicationRequest(): Request;

    /**
     * A guard the request may be served through, such as one other than the
     * default.
     *
     * @return string
     */
    abstract protected function applicationGuard(): string;
}
