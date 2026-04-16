<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Exceptions;

use Symfony\Component\HttpKernel\Exception\HttpException;

/**
 * MFA required exception.
 *
 * Thrown when a request requires multi-factor authentication but
 * the identity has not yet completed MFA verification. The
 * exception carries the available factors so the consuming
 * application can present them to the user.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 */
class MfaRequiredException extends HttpException
{
    /**
     * Create a new MFA required exception.
     *
     * @param  array<string, mixed>  $factors
     * @param  string  $message
     */
    public function __construct(
        private readonly array $factors = [],
        string $message = 'Multi-factor authentication is required.',
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
