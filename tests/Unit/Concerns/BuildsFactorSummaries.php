<?php

declare(strict_types = 1);

namespace Tests\Unit\Concerns;

use SineMacula\Laravel\Mfa\Contracts\Factor;
use SineMacula\Laravel\Mfa\Enums\FactorStatus;
use SineMacula\Laravel\Mfa\Factors\FactorSummary;

/**
 * Shared FactorSummary builders for the FactorSummary test family.
 *
 * Centralises the two recurring stub-builders so each consuming test file stays
 * focused on its assertions and keeps its method count below the project's
 * max-methods-per-class threshold.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait BuildsFactorSummaries
{
    /**
     * Build a minimal summary for contract tests.
     *
     * @return \SineMacula\Laravel\Mfa\Factors\FactorSummary
     */
    protected function buildMinimalSummary(): FactorSummary
    {
        return new FactorSummary(
            id             : '01H',
            type         : 'totp',
            label          : null,
            maskedDestination: null,
            status     : FactorStatus::CONFIRMED,
            preferred: false,
            lastUsedAt: null,
        );
    }

    /**
     * Build a FactorSummary via `fromFactor()` for the given destination.
     *
     * @param  string  $destination
     * @return \SineMacula\Laravel\Mfa\Factors\FactorSummary
     *
     * @throws \PHPUnit\Framework\MockObject\Exception
     */
    protected function buildSummaryWithDestination(string $destination): FactorSummary
    {
        $factor = self::createStub(Factor::class);
        $factor->method('getFactorIdentifier')->willReturn('id');
        $factor->method('getType')->willReturn('email');
        $factor->method('getLabel')->willReturn(null);
        $factor->method('getDestination')->willReturn($destination);
        $factor->method('getStatus')->willReturn(FactorStatus::CONFIRMED);
        $factor->method('getLastUsedAt')->willReturn(null);

        return FactorSummary::fromFactor($factor);
    }
}
