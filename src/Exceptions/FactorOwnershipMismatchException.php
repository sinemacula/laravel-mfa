<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Exceptions;

use SineMacula\Laravel\Mfa\Contracts\Factor;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;

/**
 * Factor ownership mismatch exception.
 *
 * Thrown by the MFA manager when an entry-point method (`challenge`, `verify`,
 * `disable`, `enrol` for non-Eloquent factors) receives a `Factor` whose owner
 * does not match the currently authenticated identity. Closes the
 * cross-account-factor primitive: a consumer looking a factor up by an ID drawn
 * from request input cannot use it to satisfy MFA on a different identity than
 * the one that owns it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 */
final class FactorOwnershipMismatchException extends \RuntimeException
{
    /**
     * Build the exception with a deterministic message describing the detected
     * mismatch. Includes the driver name and identity FQCN but never the factor
     * identifier itself — keeps the message useful for ops without leaking
     * opaque internals to logs.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @return self
     */
    public static function for(Factor $factor, MultiFactorAuthenticatable $identity): self
    {
        return new self(
            sprintf(
                'Factor [%s] does not belong to the current identity [%s].',
                $factor->getDriver(),
                $identity::class,
            ),
        );
    }
}
