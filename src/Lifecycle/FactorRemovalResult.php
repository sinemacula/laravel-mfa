<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Lifecycle;

use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Factors\FactorSummary;
use SineMacula\Laravel\Mfa\Requirements\Requirement;

/**
 * How removing a factor ended: made, with the factor as it stood, the
 * requirement the session no longer meets, if any, and what the bound
 * `SessionRevoker` returned for the caller when it judged the session again
 * itself, or else what the bound `SessionTransition` did; or refused, with the
 * reason a caller may be told. The requirement is the session's whole
 * requirement, not what is left of it, as this package assesses it: an
 * authentication layer that judged the session again may have ended it, or
 * returned it to pending, by rules of its own, and what it returned (its new
 * pending credential, say) is the authoritative outcome.
 *
 * The completion may hold a credential, so it is held as a
 * `\SensitiveParameterValue` and read through `completion()`, and no dump shows
 * it.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class FactorRemovalResult
{
    /** @var \SensitiveParameterValue What was returned for the caller, hidden from dumps. */
    private \SensitiveParameterValue $completion;

    /**
     * Constructor.
     *
     * @param  ?\SineMacula\Laravel\Mfa\Factors\FactorSummary  $factor
     * @param  ?\SineMacula\Laravel\Mfa\Requirements\Requirement  $outstanding
     * @param  ?\SineMacula\Laravel\Mfa\Enums\FailureReason  $reason
     * @param  ?object  $completion
     */
    private function __construct(

        /** The factor as it stood, when it was removed. */
        public ?FactorSummary $factor,

        /** The requirement the session no longer meets, if any. */
        public ?Requirement $outstanding,

        /** Why the removal was refused, when it was. */
        public ?FailureReason $reason,

        // What the bound session revoker, or else the bound session transition,
        // returned for the caller, opaque to this package.
        #[\SensitiveParameter]
        ?object $completion = null,
    ) {
        $this->completion = new \SensitiveParameterValue($completion);
    }

    /**
     * A removal that was made.
     *
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
     * What the bound session revoker, or else the bound session transition,
     * returned for the caller, such as a pending session's new credential, or
     * `null`.
     *
     * @return ?object
     */
    public function completion(): ?object
    {
        /** @var ?object */
        return $this->completion->getValue();
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
