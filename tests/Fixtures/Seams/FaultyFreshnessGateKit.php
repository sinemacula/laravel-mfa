<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Seams;

use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Context\CallerContext;
use SineMacula\Laravel\Mfa\Contracts\FreshnessGate;
use SineMacula\Laravel\Mfa\Enums\Operation;
use SineMacula\Laravel\Mfa\Testing\Seams\Concerns\FreshnessGateTests;
use Tests\Fixtures\Context\Callers;

/**
 * The freshness gate kit over a gate that finds everything fresh, for running
 * its checks as PHPUnit does.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversNothing]
final class FaultyFreshnessGateKit extends TestCase
{
    use FreshnessGateTests;

    /**
     * @return \SineMacula\Laravel\Mfa\Context\CallerContext
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[\Override]
    protected function freshnessCaller(): CallerContext
    {
        return Callers::current();
    }

    /**
     * @return \SineMacula\Laravel\Mfa\Contracts\FreshnessGate
     */
    #[\Override]
    protected function freshnessGate(): FreshnessGate
    {
        return new FaultySeams;
    }

    /**
     * @return \SineMacula\Laravel\Mfa\Contracts\FreshnessGate
     */
    #[\Override]
    protected function freshGate(): FreshnessGate
    {
        return new FaultySeams;
    }

    /**
     * @return string
     */
    #[\Override]
    protected function freshOperation(): string
    {
        return Operation::ADD_FACTOR->value;
    }
}
