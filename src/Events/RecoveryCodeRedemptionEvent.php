<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Events;

use SineMacula\Laravel\Mfa\Enums\Purpose;

/**
 * Base of the events a recovery code redemption dispatches: each says how many
 * codes of the set remain unused and what the redemption was for.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
abstract readonly class RecoveryCodeRedemptionEvent extends ContextEvent
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

        /** What the code was redeemed for: a sign-in, a step-up or a reauthentication. */
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
