<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Events;

use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Factors\FactorSummary;

/**
 * Dispatched once per attempt that passes: a factor, or a recovery code, proved
 * for a purpose.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class VerificationPassed extends ContextEvent
{
    /**
     * @param  array<string, int|string|null>  $context
     * @param  ?\SineMacula\Laravel\Mfa\Factors\FactorSummary  $factor
     * @param  string  $type
     * @param  \SineMacula\Laravel\Mfa\Enums\Purpose  $purpose
     * @param  ?string  $challengeId
     */
    public function __construct(

        // Who and what the event is about.
        array $context,

        /** The factor proved, or null for a recovery code. */
        public ?FactorSummary $factor,

        /** The type proved: the factor's, or `recovery_code`. */
        public string $type,

        /** What the proof was for. */
        public Purpose $purpose,

        /** The authentication challenge the attempt went through, if any. */
        public ?string $challengeId = null,
    ) {
        parent::__construct($context);
    }

    /**
     * @return \SineMacula\Laravel\Mfa\Enums\Purpose
     */
    #[\Override]
    public function purpose(): Purpose
    {
        return $this->purpose;
    }
}
