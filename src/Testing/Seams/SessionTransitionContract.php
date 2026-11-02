<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Testing\Seams;

use PHPUnit\Framework\Assert;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\SessionTransition;
use SineMacula\Laravel\Mfa\Requirements\Requirement;

/**
 * What every `SessionTransition` must guarantee, as an assertion: returning a
 * session to pending either returns, meaning access is gated until the
 * requirement is met, or refuses by throwing a `RuntimeException`, so the
 * change it is part of rolls back; it never fails in any other way.
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
     * Returning the session to pending returns, or refuses by throwing a
     * `RuntimeException`.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\SessionTransition  $transition
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @return void
     */
    public static function assertReturnsOrRefusesByThrowing(SessionTransition $transition, MultiFactorAuthenticatable $identity, string $application): void
    {
        $outcome = null;

        try {
            $transition->returnToPending($identity, $application, Requirement::none()->withAdditionalVerification());
        } catch (\Throwable $exception) {
            $outcome = $exception;
        }

        Assert::assertTrue($outcome === null || $outcome instanceof \RuntimeException, 'Returning a session to pending must return, or refuse by throwing a RuntimeException.');
    }
}
