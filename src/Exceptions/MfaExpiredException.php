<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Exceptions;

use SineMacula\Laravel\Mfa\Support\FactorSummary;
use Symfony\Component\HttpKernel\Exception\HttpException;

/**
 * Thrown when a previously completed MFA verification has expired and
 * the current identity must re-verify.
 *
 * Carries a list of `FactorSummary` records describing the factors the
 * identity has available for re-verification — the consuming
 * application uses this payload to render a re-verify UI without
 * needing to know anything about the package's internal factor
 * representation.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 */
class MfaExpiredException extends HttpException
{
    /**
     * Constructor.
     *
     * @param  list<\SineMacula\Laravel\Mfa\Support\FactorSummary>  $factors
     * @param  string  $message
     */
    public function __construct(

        /** Factor summaries available to the current identity. */
        private readonly array $factors = [],

        string $message = 'Multi-factor authentication has expired.',

    ) {
        parent::__construct(401, $message);
    }

    /**
     * Return the factor summaries available to the current identity.
     *
     * @return list<\SineMacula\Laravel\Mfa\Support\FactorSummary>
     */
    public function getFactors(): array
    {
        return $this->factors;
    }
}
