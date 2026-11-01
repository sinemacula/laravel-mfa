<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Events;

use SineMacula\Laravel\Mfa\Enums\Purpose;

/**
 * Dispatched when a redemption leaves the recovery code set at or below its low
 * count, so the application can prompt for a new set.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class RecoveryCodesLow extends ContextEvent
{
    /**
     * Constructor.
     *
     * @param  array<string, int|string|null>  $context
     * @param  int  $remaining
     * @param  \SineMacula\Laravel\Mfa\Enums\Purpose  $purpose
     */
    public function __construct(

        // Who and what the event is about.
        array $context,

        /** How many codes of the set remain unused. */
        public int $remaining,

        /** What the redemption that left the set low was for. */
        public Purpose $purpose,
    ) {
        parent::__construct($context);
    }

    /**
     * What the action the event reports was for.
     *
     * @return \SineMacula\Laravel\Mfa\Enums\Purpose
     */
    #[\Override]
    public function purpose(): Purpose
    {
        return $this->purpose;
    }
}
