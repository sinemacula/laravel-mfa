<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Passkeys;

use SineMacula\Laravel\Mfa\Enums\FailureReason;

/**
 * How a request for a passkey's assertion ended: started with the client's
 * options, or refused with no ceremony begun.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class AssertionRequest
{
    /**
     * @param  array<string, mixed>  $options
     * @param  ?\SineMacula\Laravel\Mfa\Enums\FailureReason  $reason
     */
    private function __construct(

        /** Empty when refused. */
        public array $options,

        /** Null when started. */
        public ?FailureReason $reason,
    ) {}

    /**
     * @param  array<string, mixed>  $options
     * @return self
     */
    public static function started(array $options): self
    {
        return new self($options, null);
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
    public function hasStarted(): bool
    {
        return $this->reason === null;
    }
}
