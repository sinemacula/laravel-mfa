<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\RecoveryCodes;

use Carbon\CarbonImmutable;

/**
 * An identity's recovery code set, without codes or hashes.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class RecoveryCodeStatus
{
    /**
     * @param  int  $remaining
     * @param  int  $generation
     * @param  ?\Carbon\CarbonImmutable  $generatedAt
     */
    public function __construct(

        /** Codes neither used nor replaced. */
        public int $remaining,

        /** 0 before the first set. */
        public int $generation,

        /** Null when there is no set. */
        public ?CarbonImmutable $generatedAt,
    ) {}

    /**
     * Whether a set exists, used up or not.
     *
     * @return bool
     */
    public function exists(): bool
    {
        return $this->generatedAt !== null;
    }
}
