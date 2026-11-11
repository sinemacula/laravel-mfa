<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Lifecycle;

use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Factors\FactorSummary;
use SineMacula\Laravel\Mfa\Requirements\Requirement;

/**
 * How removing a factor ended. When the bound `SessionRevoker` or
 * `SessionTransition` returned a completion, that outcome is authoritative.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class FactorRemovalResult
{
    /** @var \SensitiveParameterValue May hold a credential, so it is hidden from dumps. */
    private \SensitiveParameterValue $completion;

    /**
     * @param  ?\SineMacula\Laravel\Mfa\Factors\FactorSummary  $factor
     * @param  ?\SineMacula\Laravel\Mfa\Requirements\Requirement  $outstanding
     * @param  ?\SineMacula\Laravel\Mfa\Enums\FailureReason  $reason
     * @param  ?object  $completion
     */
    private function __construct(

        /** As it stood when removed. */
        public ?FactorSummary $factor,

        /** The whole requirement the session no longer meets, if any. */
        public ?Requirement $outstanding,

        /** Set only when refused. */
        public ?FailureReason $reason,

        // Returned by the bound session revoker or transition; opaque here.
        #[\SensitiveParameter]
        ?object $completion = null,
    ) {
        $this->completion = new \SensitiveParameterValue($completion);
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Factors\FactorSummary  $factor
     * @param  ?\SineMacula\Laravel\Mfa\Requirements\Requirement  $outstanding
     * @param  ?object  $completion
     * @return self
     */
    public static function made(FactorSummary $factor, ?Requirement $outstanding, #[\SensitiveParameter] ?object $completion = null): self
    {
        return new self($factor, $outstanding, null, $completion);
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Enums\FailureReason  $reason
     * @return self
     */
    public static function refused(FailureReason $reason): self
    {
        return new self(null, null, $reason);
    }

    /**
     * What the session revoker or transition returned, such as a new pending
     * credential.
     *
     * @return ?object
     */
    public function completion(): ?object
    {
        /** @var ?object */
        return $this->completion->getValue();
    }

    /**
     * @return bool
     */
    public function wasMade(): bool
    {
        return $this->reason === null;
    }
}
