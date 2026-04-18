<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Exceptions;

use SineMacula\Laravel\Mfa\Contracts\Factor;

/**
 * Factor driver mismatch exception.
 *
 * Thrown by the MFA manager when `challenge()` or `verify()` is called with a
 * driver name that does not match the supplied factor's registered driver.
 * Routing one driver's logic through a factor registered against another would
 * produce confusing persistence, transport, and audit-event semantics — failing
 * loudly surfaces the caller bug at the entry point rather than letting it leak
 * into the pipeline.
 *
 * Extends `\InvalidArgumentException` so generic catch blocks and any existing
 * contributor expectations at that type continue to match; the dedicated
 * subclass lets consumers distinguish mismatch faults from other argument
 * errors when they want typed handling.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 */
final class FactorDriverMismatchException extends \InvalidArgumentException
{
    /**
     * Build the exception with a deterministic message describing the detected
     * mismatch. Includes the requested driver name and the factor's registered
     * driver so the root cause is visible in the stack trace without any
     * further inspection.
     *
     * @param  string  $requested
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @return self
     */
    public static function for(string $requested, Factor $factor): self
    {
        return new self(
            sprintf(
                'Driver mismatch: requested [%s] but factor is registered against [%s].',
                $requested,
                $factor->getDriver(),
            ),
        );
    }
}
