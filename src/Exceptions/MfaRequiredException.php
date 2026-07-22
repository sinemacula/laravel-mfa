<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Exceptions;

/**
 * Thrown when a request requires multi-factor authentication but the current
 * identity has not completed MFA verification (either has no factors set up, or
 * has factors but has never verified against them).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 */
final class MfaRequiredException extends AbstractMfaHttpException
{
    /**
     * Constructor.
     *
     * @param  list<\SineMacula\Laravel\Mfa\Support\FactorSummary>  $factors
     * @param  string  $message
     */
    public function __construct(
        array $factors = [],
        string $message = 'Multi-factor authentication is required.',
    ) {
        parent::__construct($factors, $message);
    }
}
