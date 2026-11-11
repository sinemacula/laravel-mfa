<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Testing\Seams\Concerns;

use Illuminate\Http\Request;
use SineMacula\Laravel\Mfa\Contracts\ApplicationResolver;
use SineMacula\Laravel\Mfa\Testing\Seams\ApplicationResolverContract;

/**
 * The `ApplicationResolver` contract kit; each check delegates to
 * `ApplicationResolverContract`.
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
     * @return void
     */
    public function testApplicationResolverNamesOneApplication(): void
    {
        ApplicationResolverContract::assertNamesOneApplication($this->applicationResolver(), $this->applicationRequest());
    }

    /**
     * @return \SineMacula\Laravel\Mfa\Contracts\ApplicationResolver
     */
    abstract protected function applicationResolver(): ApplicationResolver;

    /**
     * @return \Illuminate\Http\Request
     */
    abstract protected function applicationRequest(): Request;
}
