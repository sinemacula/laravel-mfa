<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Exceptions;

/**
 * Thrown when a previously completed MFA verification has expired and the
 * current identity must re-verify.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 */
final class MfaExpiredException extends AbstractMfaHttpException
{
    /**
     * Constructor.
     *
     * @param  list<\SineMacula\Laravel\Mfa\Support\FactorSummary>  $factors
     * @param  string  $message
     */
    public function __construct(
        array $factors = [],
        string $message = 'Multi-factor authentication has expired.',
    ) {
        parent::__construct($factors, $message);
    }
}
