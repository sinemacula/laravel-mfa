<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\RecoveryCodes;

use SineMacula\Laravel\Mfa\Enums\FailureReason;

/**
 * How a request for a new recovery code set ended: generated, with its codes,
 * once, as secrets for the response, or refused, with the reason a caller may
 * be told, leaving any earlier set as it was.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class RecoveryCodeGeneration
{
    /**
     * Constructor.
     *
     * @param  list<\SineMacula\Laravel\Mfa\Secrets\RevealedSecret>  $codes
     * @param  ?\SineMacula\Laravel\Mfa\Enums\FailureReason  $reason
     */
    private function __construct(

        /** The set's codes, when one was generated. */
        public array $codes,

        /** Why the set was refused, when it was. */
        public ?FailureReason $reason,
    ) {}

    /**
     * A set that was generated.
     *
     * @param  list<\SineMacula\Laravel\Mfa\Secrets\RevealedSecret>  $codes
     * @return self
     */
    public static function generated(array $codes): self
    {
        return new self($codes, null);
    }

    /**
     * A set refused for the reason.
     *
     * @param  \SineMacula\Laravel\Mfa\Enums\FailureReason  $reason
     * @return self
     */
    public static function refused(FailureReason $reason): self
    {
        return new self([], $reason);
    }

    /**
     * Whether a set was generated.
     *
     * @return bool
     */
    public function wasGenerated(): bool
    {
        return $this->reason === null;
    }
}
