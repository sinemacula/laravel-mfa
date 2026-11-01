<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Events;

/**
 * Dispatched when a new recovery code set is generated, replacing any earlier
 * one. It carries the set's size and generation, never a code.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class RecoveryCodesGenerated extends ContextEvent
{
    /**
     * Constructor.
     *
     * @param  array<string, int|string|null>  $context
     * @param  int  $count
     * @param  int  $generation
     * @param  ?\SineMacula\Laravel\Mfa\Events\Actor  $actor
     */
    public function __construct(

        // Who and what the event is about.
        array $context,

        /** How many codes the set holds. */
        public int $count,

        /** The set's generation. */
        public int $generation,

        /** Who took the action, when it was someone other than the identity. */
        public ?Actor $actor = null,
    ) {
        parent::__construct($context);
    }
}
