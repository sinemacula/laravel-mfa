<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Testing\Seams;

use PHPUnit\Framework\Assert;
use SineMacula\Laravel\Mfa\Contracts\SessionTransition;
use SineMacula\Laravel\Mfa\Enums\FactorChangeMade;
use SineMacula\Laravel\Mfa\Requirements\Requirement;
use SineMacula\Laravel\Mfa\Requirements\SessionChange;

/**
 * What every `SessionTransition` must guarantee: after each factor change,
 * short or not, it returns or throws a `RuntimeException` so the change rolls
 * back, and fails no other way. The return value is the layer's own and not
 * checked.
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
     * `$arrange` runs per change so an earlier one cannot leave a later one
     * only an ended session to judge.
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
