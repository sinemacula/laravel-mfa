<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Verification;

use SineMacula\Laravel\Mfa\Context\Caller;
use SineMacula\Laravel\Mfa\Enums\Purpose;

/**
 * Which purposes a verification, a code or a ceremony may be made for.
 *
 * A pending session is always completing its sign-in. An active session steps
 * up unless the caller asks for `sign_in`, which is how a sign-in gated by the
 * middleware completes with no authentication layer. Everything else (a code
 * confirming an enrolment, or proving the first factor again) is not made here.
 * Codes are bound to their purpose, so sending and verifying must name the same
 * one.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class PurposeRule
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * The purpose the caller's request is made for, or `null` when the caller
     * may not make it for the purpose it asked for.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\Caller  $caller
     * @param  ?\SineMacula\Laravel\Mfa\Enums\Purpose  $requested
     * @return ?\SineMacula\Laravel\Mfa\Enums\Purpose
     */
    public static function resolve(Caller $caller, ?Purpose $requested): ?Purpose
    {
        if ($caller->pending !== null) {
            return $requested === null || $requested === Purpose::SIGN_IN ? Purpose::SIGN_IN : null;
        }

        return match ($requested) {
            null, Purpose::STEP_UP => Purpose::STEP_UP,
            Purpose::SIGN_IN       => Purpose::SIGN_IN,
            default                => null,
        };
    }
}
