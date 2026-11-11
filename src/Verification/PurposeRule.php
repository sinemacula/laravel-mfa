<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Verification;

use SineMacula\Laravel\Mfa\Context\Caller;
use SineMacula\Laravel\Mfa\Enums\Purpose;

/**
 * Which purposes a verification, code or ceremony may be made for; sending and
 * verifying must name the same one.
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
     * A pending session only signs in; an active one steps up unless it asks
     * for `sign_in`. `null` refuses the request.
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
