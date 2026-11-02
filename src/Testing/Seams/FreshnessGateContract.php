<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Testing\Seams;

use PHPUnit\Framework\Assert;
use SineMacula\Laravel\Mfa\Contracts\FreshnessGate;
use SineMacula\Laravel\Mfa\Requirements\Requirement;

/**
 * What every `FreshnessGate` must guarantee, as assertions: a name that is not
 * an operation's, and an operation with no requirement from either side, are
 * never fresh, a caller's requirement with no maximum age is refused, how long
 * a session is fresh is either nothing or a time still to come that the session
 * is fresh until, and the requirement it says it holds a session to asks at
 * least what the caller asks.
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
     * A caller's requirement with a part that carries no maximum age is refused
     * with an `InvalidArgumentException`.
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

    /**
     * An operation that is not fresh has no time it is fresh until.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\FreshnessGate  $gate
     * @return void
     */
    public static function assertAnOperationThatIsNotFreshHasNoDeadline(FreshnessGate $gate): void
    {
        Assert::assertFalse($gate->isFresh(self::UNCONFIGURED));
        Assert::assertNull($gate->freshUntil(self::UNCONFIGURED), 'An operation that is not fresh must have no deadline.');
    }

    /**
     * A deadline is not in the past, and the session is fresh while it holds.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\FreshnessGate  $gate
     * @param  string  $operation
     * @return void
     */
    public static function assertADeadlineIsAheadAndMeansFresh(FreshnessGate $gate, string $operation): void
    {
        $until = $gate->freshUntil($operation);

        Assert::assertNotNull($until, 'A session fresh for the operation must say until when.');
        Assert::assertFalse($until->isPast(), 'A deadline must not be in the past.');
        Assert::assertTrue($gate->isFresh($operation), 'A session with a deadline must be fresh.');
    }

    /**
     * The requirement the gate holds a session to is none for an operation with
     * no requirement from either side, and asks at least what the caller asks,
     * so judging it on some of the session's proofs can never ask less than the
     * gate does.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\FreshnessGate  $gate
     * @return void
     */
    public static function assertTheRequirementAsksWhatTheCallerAsks(FreshnessGate $gate): void
    {
        Assert::assertNull($gate->requirement(self::UNCONFIGURED), 'An operation with no requirement must have none to judge by.');

        $asked  = Requirement::none()->withAdditionalVerification(300);
        $answer = $gate->requirement(self::UNCONFIGURED, $asked);

        Assert::assertNotNull($answer, 'A caller\'s requirement must be answered with a requirement.');
        Assert::assertSame($answer->toArray(), Requirement::strictest($answer, $asked)->toArray(), 'The requirement must ask at least what the caller asks.');
    }
}
