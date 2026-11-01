<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Events;

/**
 * Dispatched when someone resets the identity's factors: every factor removed,
 * lockouts lifted, sessions revoked and proofs invalidated.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class FactorsReset extends ContextEvent
{
    /**
     * Constructor.
     *
     * @param  array<string, int|string|null>  $context
     * @param  \SineMacula\Laravel\Mfa\Events\Actor  $actor
     * @param  ?string  $reason
     * @param  bool  $reenrollmentRequired
     */
    public function __construct(

        // Who and what the event is about.
        array $context,

        /** Who reset the factors. */
        public Actor $actor,

        /** The reason the actor gave, if any. */
        public ?string $reason = null,

        /** Whether the identity must enrol again at its next sign-in. */
        public bool $reenrollmentRequired = true,
    ) {
        parent::__construct($context);
    }
}
