<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Lifecycle;

use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Factors\FactorSummary;
use SineMacula\Laravel\Mfa\Requirements\Requirement;

/**
 * How removing a factor ended: made, with the factor as it stood and the
 * requirement the session no longer meets, if any; or refused, with the reason
 * a caller may be told. The requirement is the session's whole requirement, not
 * what is left of it.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class FactorRemovalResult
{
    /**
     * Constructor.
     *
     * @param  ?\SineMacula\Laravel\Mfa\Factors\FactorSummary  $factor
     * @param  ?\SineMacula\Laravel\Mfa\Requirements\Requirement  $outstanding
     * @param  ?\SineMacula\Laravel\Mfa\Enums\FailureReason  $reason
     */
    private function __construct(

        /** The factor as it stood, when it was removed. */
        public ?FactorSummary $factor,

        /** The requirement the session no longer meets, if any. */
        public ?Requirement $outstanding,

        /** Why the removal was refused, when it was. */
        public ?FailureReason $reason,
    ) {}

    /**
     * A removal that was made.
     *
     * @param  \SineMacula\Laravel\Mfa\Factors\FactorSummary  $factor
     * @param  ?\SineMacula\Laravel\Mfa\Requirements\Requirement  $outstanding
     * @return self
     */
    public static function made(FactorSummary $factor, ?Requirement $outstanding): self
    {
        return new self($factor, $outstanding, null);
    }

    /**
     * A removal refused for the reason.
     *
     * @param  \SineMacula\Laravel\Mfa\Enums\FailureReason  $reason
     * @return self
     */
    public static function refused(FailureReason $reason): self
    {
        return new self(null, null, $reason);
    }

    /**
     * Whether the factor was removed.
     *
     * @return bool
     */
    public function wasMade(): bool
    {
        return $this->reason === null;
    }
}
