<?php

declare(strict_types = 1);

namespace Tests\Unit\Concerns;

use SineMacula\Laravel\Mfa\Contracts\Factor;
use SineMacula\Laravel\Mfa\Support\FactorSummary;

/**
 * Shared FactorSummary builders for the FactorSummary test family.
 *
 * Centralises the two recurring stub-builders so each consuming test file stays
 * focused on its assertions and keeps its method count below the project's
 * max-methods-per-class threshold.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 *
 * @internal
 */
trait BuildsFactorSummaries
{
    /**
     * Build a minimal summary for contract tests.
     *
     * @return \SineMacula\Laravel\Mfa\Support\FactorSummary
     */
    protected function buildMinimalSummary(): FactorSummary
    {
        return new FactorSummary(
            id             : '01H',
            driver         : 'totp',
            label          : null,
            maskedRecipient: null,
            verifiedAt     : null,
        );
    }

    /**
     * Build a FactorSummary via `fromFactor()` for the given recipient.
     *
     * @param  string  $recipient
     * @return \SineMacula\Laravel\Mfa\Support\FactorSummary
     *
     * @throws \PHPUnit\Framework\MockObject\Exception
     */
    protected function buildSummaryWithRecipient(string $recipient): FactorSummary
    {
        $factor = self::createStub(Factor::class);
        $factor->method('getFactorIdentifier')->willReturn('id');
        $factor->method('getDriver')->willReturn('email');
        $factor->method('getLabel')->willReturn(null);
        $factor->method('getRecipient')->willReturn($recipient);
        $factor->method('getVerifiedAt')->willReturn(null);

        return FactorSummary::fromFactor($factor);
    }
}
