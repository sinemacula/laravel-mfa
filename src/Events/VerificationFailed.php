<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Events;

use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Factors\FactorSummary;

/**
 * Dispatched once per attempt that fails, with the machine-readable reason. A
 * check against the whole recovery code set is one attempt.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class VerificationFailed extends ContextEvent
{
    /**
     * Constructor.
     *
     * @param  array<string, int|string|null>  $context
     * @param  ?\SineMacula\Laravel\Mfa\Factors\FactorSummary  $factor
     * @param  ?string  $type
     * @param  \SineMacula\Laravel\Mfa\Enums\Purpose  $purpose
     * @param  \SineMacula\Laravel\Mfa\Enums\FailureReason  $reason
     * @param  ?string  $challengeId
     */
    public function __construct(

        // Who and what the event is about.
        array $context,

        /** The factor the attempt was against, or null when none was found or a recovery code was tried. */
        public ?FactorSummary $factor,

        /** The type tried, or null when it is not known. */
        public ?string $type,

        /** What the attempt was for. */
        public Purpose $purpose,

        /** Why the attempt failed. */
        public FailureReason $reason,

        /** The authentication challenge the attempt went through, if any. */
        public ?string $challengeId = null,
    ) {
        parent::__construct($context);
    }
}
