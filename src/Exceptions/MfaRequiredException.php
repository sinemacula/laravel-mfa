<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Exceptions;

use SineMacula\Laravel\Mfa\Support\FactorSummary;
use Symfony\Component\HttpKernel\Exception\HttpException;

/**
 * Thrown when a request requires multi-factor authentication but the
 * current identity has not completed MFA verification (either has no
 * factors set up, or has factors but has never verified against them).
 *
 * Carries a list of `FactorSummary` records describing the factors the
 * identity has available — the consuming application uses this payload
 * to render a verification UI without needing to know anything about
 * the package's internal factor representation.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 */
final class MfaRequiredException extends HttpException
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

        string $message = 'Multi-factor authentication is required.',

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
