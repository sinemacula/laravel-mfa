<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Testing\Seams;

use PHPUnit\Framework\Assert;
use SineMacula\Laravel\Mfa\Context\CallerContext;
use SineMacula\Laravel\Mfa\Contracts\FreshnessGate;
use SineMacula\Laravel\Mfa\Requirements\Requirement;

/**
 * What every `FreshnessGate` must guarantee: an invalid name or an operation
 * with no requirement is never fresh, an unbounded caller requirement throws, a
 * deadline is absent or ahead, and its requirement asks at least the caller's.
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
     * @param  \SineMacula\Laravel\Mfa\Contracts\FreshnessGate  $gate
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContext  $caller
     * @return void
     */
    public static function assertANameThatIsNoOperationIsNeverFresh(FreshnessGate $gate, CallerContext $caller): void
    {
        Assert::assertFalse($gate->isFresh($caller, 'Not An Operation'), 'A name that is not an operation\'s must never be fresh.');
    }

    /**
     * No requirement of its own and none from the caller.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\FreshnessGate  $gate
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContext  $caller
     * @return void
     */
    public static function assertAnOperationWithNoRequirementIsNeverFresh(FreshnessGate $gate, CallerContext $caller): void
    {
        Assert::assertFalse($gate->isFresh($caller, self::UNCONFIGURED), 'An operation with no requirement must never be fresh.');
    }

    /**
     * A part with no maximum age throws `InvalidArgumentException`.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\FreshnessGate  $gate
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContext  $caller
     * @return void
     */
    public static function assertAnUnboundedRequirementIsRefused(FreshnessGate $gate, CallerContext $caller): void
    {
        $outcome = null;

        try {
            $gate->isFresh($caller, self::UNCONFIGURED, Requirement::none()->withAdditionalVerification());
        } catch (\Throwable $exception) {
            $outcome = $exception;
        }

        Assert::assertInstanceOf(\InvalidArgumentException::class, $outcome, 'A caller\'s requirement with no maximum age must be refused.');
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Contracts\FreshnessGate  $gate
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContext  $caller
     * @return void
     */
    public static function assertAnOperationThatIsNotFreshHasNoDeadline(FreshnessGate $gate, CallerContext $caller): void
    {
        Assert::assertFalse($gate->isFresh($caller, self::UNCONFIGURED));
        Assert::assertNull($gate->freshUntil($caller, self::UNCONFIGURED), 'An operation that is not fresh must have no deadline.');
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Contracts\FreshnessGate  $gate
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContext  $caller
     * @param  string  $operation
     * @return void
     */
    public static function assertADeadlineIsAheadAndMeansFresh(FreshnessGate $gate, CallerContext $caller, string $operation): void
    {
        $until = $gate->freshUntil($caller, $operation);

        Assert::assertNotNull($until, 'A session fresh for the operation must say until when.');
        Assert::assertFalse($until->isPast(), 'A deadline must not be in the past.');
        Assert::assertTrue($gate->isFresh($caller, $operation), 'A session with a deadline must be fresh.');
    }

    /**
     * None when neither side asks, so judging only some of the session's proofs
     * can never ask less than the gate does.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\FreshnessGate  $gate
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContext  $caller
     * @return void
     */
    public static function assertTheRequirementAsksWhatTheCallerAsks(FreshnessGate $gate, CallerContext $caller): void
    {
        Assert::assertNull($gate->requirement($caller, self::UNCONFIGURED), 'An operation with no requirement must have none to judge by.');

        $asked  = Requirement::none()->withAdditionalVerification(300);
        $answer = $gate->requirement($caller, self::UNCONFIGURED, $asked);

        Assert::assertNotNull($answer, 'A caller\'s requirement must be answered with a requirement.');
        Assert::assertSame($answer->toArray(), Requirement::strictest($answer, $asked)->toArray(), 'The requirement must ask at least what the caller asks.');
    }
}
