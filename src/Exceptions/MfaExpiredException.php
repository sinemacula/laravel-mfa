<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Exceptions;

use Symfony\Component\HttpKernel\Exception\HttpException;

/**
 * MFA expired exception.
 *
 * Thrown when a previously completed MFA verification has expired
 * and the identity must re-verify. The exception carries the
 * available factors so the consuming application can prompt the
 * user to verify again.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 */
class MfaExpiredException extends HttpException
{
    /**
     * Create a new MFA expired exception.
     *
     * @param  array<string, mixed>  $factors
     * @param  string  $message
     */
    public function __construct(
        private readonly array $factors = [],
        string $message = 'Multi-factor authentication has expired.',
    ) {
        parent::__construct(401, $message);
    }

    /**
     * Get the available factors data.
     *
     * @return array<string, mixed>
     */
    public function getFactors(): array
    {
        return $this->factors;
    }
}
