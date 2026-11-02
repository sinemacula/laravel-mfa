<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Testing\Seams;

use PHPUnit\Framework\Assert;
use SineMacula\Laravel\Mfa\Contracts\FreshnessGate;
use SineMacula\Laravel\Mfa\Requirements\Requirement;

/**
 * What every `FreshnessGate` must guarantee, as assertions: a name that is not
 * an operation's, and an operation with no requirement from either side, are
 * never fresh, and a caller's requirement with no maximum age is refused.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
final class FreshnessGateContract
{
    /** @var string An operation no application configures. */
    public const string UNCONFIGURED = 'contract.unconfigured_operation';

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * A name that is not in the form an operation's takes is never fresh.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\FreshnessGate  $gate
     * @return void
     */
    public static function assertANameThatIsNoOperationIsNeverFresh(FreshnessGate $gate): void
    {
        Assert::assertFalse($gate->isFresh('Not An Operation'), 'A name that is not an operation\'s must never be fresh.');
    }

    /**
     * An operation with no requirement of its own and none from the caller is
     * never fresh.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\FreshnessGate  $gate
     * @return void
     */
    public static function assertAnOperationWithNoRequirementIsNeverFresh(FreshnessGate $gate): void
    {
        Assert::assertFalse($gate->isFresh(self::UNCONFIGURED), 'An operation with no requirement must never be fresh.');
    }

    /**
     * A caller's requirement with a part that carries no maximum age is
     * refused with an `InvalidArgumentException`.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\FreshnessGate  $gate
     * @return void
     */
    public static function assertAnUnboundedRequirementIsRefused(FreshnessGate $gate): void
    {
        $outcome = null;

        try {
            $gate->isFresh(self::UNCONFIGURED, Requirement::none()->withAdditionalVerification());
        } catch (\Throwable $exception) {
            $outcome = $exception;
        }

        Assert::assertInstanceOf(\InvalidArgumentException::class, $outcome, 'A caller\'s requirement with no maximum age must be refused.');
    }
}
