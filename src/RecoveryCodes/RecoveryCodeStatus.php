<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\RecoveryCodes;

use Carbon\CarbonImmutable;

/**
 * Where an identity's recovery code set stands, without a code or a hash: how
 * many of its codes are unused, its generation and when it was generated. An
 * identity that has never had a set, or whose set was removed with its last
 * factor, has none: no time, and nothing remaining.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class RecoveryCodeStatus
{
    /**
     * Constructor.
     *
     * @param  int  $remaining
     * @param  int  $generation
     * @param  ?\Carbon\CarbonImmutable  $generatedAt
     */
    public function __construct(

        /** How many codes of the current set are neither used nor replaced. */
        public int $remaining,

        /** The generation of the current set: 0 before the first. */
        public int $generation,

        /** When the current set was generated, or null when there is none. */
        public ?CarbonImmutable $generatedAt,
    ) {}

    /**
     * Determine whether the identity has a set, used up or not.
     *
     * @return bool
     */
    public function exists(): bool
    {
        return $this->generatedAt !== null;
    }
}
