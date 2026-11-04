<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Testing\Seams;

use PHPUnit\Framework\Assert;
use SineMacula\Laravel\Mfa\Contracts\SessionTransition;
use SineMacula\Laravel\Mfa\Enums\FactorChangeMade;
use SineMacula\Laravel\Mfa\Requirements\Requirement;
use SineMacula\Laravel\Mfa\Requirements\SessionChange;

/**
 * What every `SessionTransition` must guarantee, as an assertion: judging a
 * session again after each change to its factors, whether or not the package
 * finds it short, either returns, meaning the change was handled, or refuses by
 * throwing a `RuntimeException`, so the change it is part of rolls back; it
 * never fails in any other way. What it returns is the layer's own, so the kit
 * does not look into it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
final class SessionTransitionContract
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Each change, with a shortfall and without, returns or refuses by throwing
     * a `RuntimeException`. Each is arranged afresh, so no earlier one leaves a
     * later one only a session already ended to judge.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\SessionTransition  $transition
     * @param  \Closure(\SineMacula\Laravel\Mfa\Enums\FactorChangeMade): \SineMacula\Laravel\Mfa\Requirements\SessionChange  $arrange
     * @return void
     */
    public static function assertReturnsOrRefusesByThrowing(SessionTransition $transition, \Closure $arrange): void
    {
        foreach (FactorChangeMade::cases() as $change) {
            foreach ([Requirement::none()->withAdditionalVerification(), null] as $outstanding) {
                $made = $arrange($change);

                self::assertHandled($transition, new SessionChange($made->identity, $made->application, $made->session, $made->change, $made->factor, $outstanding));
            }
        }
    }

    /**
     * The one change returns, or refuses by throwing a `RuntimeException`.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\SessionTransition  $transition
     * @param  \SineMacula\Laravel\Mfa\Requirements\SessionChange  $change
     * @return void
     */
    private static function assertHandled(SessionTransition $transition, SessionChange $change): void
    {
        $outcome = null;

        try {
            $transition->factorChanged($change);
        } catch (\Throwable $exception) {
            $outcome = $exception;
        }

        Assert::assertTrue(
            $outcome === null || $outcome instanceof \RuntimeException,
            sprintf('Judging a session after [%s] must return, or refuse by throwing a RuntimeException.', $change->change->value),
        );
    }
}
