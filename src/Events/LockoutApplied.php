<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Events;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Mfa\Factors\FactorSummary;

/**
 * Dispatched when too many failed attempts lock a factor, or the identity
 * across its factors.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class LockoutApplied extends ContextEvent
{
    /**
     * Constructor.
     *
     * @param  array<string, int|string|null>  $context
     * @param  ?\SineMacula\Laravel\Mfa\Factors\FactorSummary  $factor
     * @param  \Carbon\CarbonImmutable  $lockedUntil
     */
    public function __construct(

        // Who and what the event is about.
        array $context,

        /** The factor locked, or null when the identity is. */
        public ?FactorSummary $factor,

        /** When the lockout ends. */
        public CarbonImmutable $lockedUntil,
    ) {
        parent::__construct($context);
    }
}
