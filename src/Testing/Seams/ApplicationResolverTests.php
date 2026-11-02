<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Testing\Seams;

use Illuminate\Http\Request;
use SineMacula\Laravel\Mfa\Contracts\ApplicationResolver;

/**
 * The `ApplicationResolver` contract kit: a request names one application, by a
 * name that is not blank.
 *
 * A test case proves its implementation by using this trait and implementing
 * the hooks; each check delegates to `ApplicationResolverContract`.
 *
 * @phpstan-require-extends \PHPUnit\Framework\TestCase
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
trait ApplicationResolverTests
{
    /**
     * The request's application is named, the same way each time.
     *
     * @return void
     */
    public function testApplicationResolverNamesOneApplication(): void
    {
        ApplicationResolverContract::assertNamesOneApplication($this->applicationResolver(), $this->applicationRequest());
    }

    /**
     * The resolver under test.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\ApplicationResolver
     */
    abstract protected function applicationResolver(): ApplicationResolver;

    /**
     * A request for an application.
     *
     * @return \Illuminate\Http\Request
     */
    abstract protected function applicationRequest(): Request;
}
