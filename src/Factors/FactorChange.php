<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Factors;

use SineMacula\Laravel\Mfa\Enums\FailureReason;

/**
 * How a change to a factor's label or preference ended.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class FactorChange
{
    /**
     * @param  ?\SineMacula\Laravel\Mfa\Factors\FactorSummary  $factor
     * @param  ?\SineMacula\Laravel\Mfa\Enums\FailureReason  $reason
     */
    private function __construct(

        /** The factor as it now stands; null when refused. */
        public ?FactorSummary $factor,

        /** Null when made. */
        public ?FailureReason $reason,
    ) {}

    /**
     * @param  \SineMacula\Laravel\Mfa\Factors\FactorSummary  $factor
     * @return self
     */
    public static function made(FactorSummary $factor): self
    {
        return new self($factor, null);
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Enums\FailureReason  $reason
     * @return self
     */
    public static function refused(FailureReason $reason): self
    {
        return new self(null, $reason);
    }

    /**
     * @return bool
     */
    public function wasMade(): bool
    {
        return $this->reason === null;
    }
}
