<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Events;

use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Factors\FactorSummary;

/**
 * Dispatched when a code is sent by SMS or email for a factor. It names the
 * factor's type and masked destination, never the code.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class CodeSent extends ContextEvent
{
    /**
     * @param  array<string, int|string|null>  $context
     * @param  \SineMacula\Laravel\Mfa\Factors\FactorSummary  $factor
     * @param  \SineMacula\Laravel\Mfa\Enums\Purpose  $purpose
     * @param  ?string  $challengeId
     */
    public function __construct(

        // Who and what the event is about.
        array $context,

        /** The factor, as a summary: never the model, its secret or its full destination. */
        public FactorSummary $factor,

        /** What the code is for. */
        public Purpose $purpose,

        /** The authentication challenge the code was sent through, if any. */
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
