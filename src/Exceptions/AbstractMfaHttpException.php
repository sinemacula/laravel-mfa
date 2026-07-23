<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Exceptions;

use Symfony\Component\HttpKernel\Exception\HttpException;

/**
 * Base HTTP exception for MFA enforcement failures.
 *
 * Carries a list of `FactorSummary` records describing the factors the identity
 * has available - the consuming application uses this payload to render a
 * verification UI without needing to know anything about the package's internal
 * factor representation.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 */
abstract class AbstractMfaHttpException extends HttpException
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

        // Human-readable message surfaced to consumer UIs / logs.
        string $message = '',
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
