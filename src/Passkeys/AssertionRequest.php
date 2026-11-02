<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Passkeys;

use SineMacula\Laravel\Mfa\Enums\FailureReason;

/**
 * How a request for a passkey's assertion ended: started, with the options for
 * the client, or refused, with the reason a caller may be told, no ceremony
 * begun.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class AssertionRequest
{
    /**
     * Constructor.
     *
     * @param  array<string, mixed>  $options
     * @param  ?\SineMacula\Laravel\Mfa\Enums\FailureReason  $reason
     */
    private function __construct(

        /** The options of the assertion request, when one was started. */
        public array $options,

        /** Why the request was refused, when it was. */
        public ?FailureReason $reason,
    ) {}

    /**
     * A ceremony that was started.
     *
     * @param  array<string, mixed>  $options
     * @return self
     */
    public static function started(array $options): self
    {
        return new self($options, null);
    }

    /**
     * A request refused for the reason.
     *
     * @param  \SineMacula\Laravel\Mfa\Enums\FailureReason  $reason
     * @return self
     */
    public static function refused(FailureReason $reason): self
    {
        return new self([], $reason);
    }

    /**
     * Whether a ceremony was started.
     *
     * @return bool
     */
    public function hasStarted(): bool
    {
        return $this->reason === null;
    }
}
