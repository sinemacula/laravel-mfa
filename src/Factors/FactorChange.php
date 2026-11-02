<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Factors;

use SineMacula\Laravel\Mfa\Enums\FailureReason;

/**
 * How a change to a factor's label or preference ended: made, with the factor
 * as it now stands, or refused, with the reason a caller may be told.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class FactorChange
{
    /**
     * Constructor.
     *
     * @param  ?\SineMacula\Laravel\Mfa\Factors\FactorSummary  $factor
     * @param  ?\SineMacula\Laravel\Mfa\Enums\FailureReason  $reason
     */
    private function __construct(

        /** The factor as it now stands, when the change was made. */
        public ?FactorSummary $factor,

        /** Why the change was refused, when it was. */
        public ?FailureReason $reason,
    ) {}

    /**
     * A change that was made.
     *
     * @param  \SineMacula\Laravel\Mfa\Factors\FactorSummary  $factor
     * @return self
     */
    public static function made(FactorSummary $factor): self
    {
        return new self($factor, null);
    }

    /**
     * A change refused for the reason.
     *
     * @param  \SineMacula\Laravel\Mfa\Enums\FailureReason  $reason
     * @return self
     */
    public static function refused(FailureReason $reason): self
    {
        return new self(null, $reason);
    }

    /**
     * Whether the change was made.
     *
     * @return bool
     */
    public function wasMade(): bool
    {
        return $this->reason === null;
    }
}
