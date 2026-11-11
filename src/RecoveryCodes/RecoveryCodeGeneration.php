<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\RecoveryCodes;

use SineMacula\Laravel\Mfa\Enums\FailureReason;

/**
 * A new recovery code set with its codes revealed once, or the reason it was
 * refused, leaving any earlier set as it was.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class RecoveryCodeGeneration
{
    /**
     * @param  list<\SineMacula\Laravel\Mfa\Secrets\RevealedSecret>  $codes
     * @param  ?\SineMacula\Laravel\Mfa\Enums\FailureReason  $reason
     */
    private function __construct(

        /** Empty when refused. */
        public array $codes,

        /** Null when generated. */
        public ?FailureReason $reason,
    ) {}

    /**
     * @param  list<\SineMacula\Laravel\Mfa\Secrets\RevealedSecret>  $codes
     * @return self
     */
    public static function generated(array $codes): self
    {
        return new self($codes, null);
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Enums\FailureReason  $reason
     * @return self
     */
    public static function refused(FailureReason $reason): self
    {
        return new self([], $reason);
    }

    /**
     * @return bool
     */
    public function wasGenerated(): bool
    {
        return $this->reason === null;
    }
}
