<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Context;

use Illuminate\Http\Request;
use SineMacula\Laravel\Mfa\Context\PendingContext;
use SineMacula\Laravel\Mfa\Contracts\PendingSessionResolver;
use Tests\Fixtures\Exceptions\InvalidPendingCredentialException;

/**
 * Answers the same pending session, or none, for every request, or refuses
 * every request's credential.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class FixedPendingSessionResolver implements PendingSessionResolver
{
    /**
     * @param  ?\SineMacula\Laravel\Mfa\Context\PendingContext  $pending
     * @param  bool  $invalid
     */
    public function __construct(

        /** `null` for none. */
        private ?PendingContext $pending = null,

        /** Whether every request carries a credential that does not validate. */
        private bool $invalid = false,
    ) {}

    /**
     * @param  \Illuminate\Http\Request  $request
     * @return ?\SineMacula\Laravel\Mfa\Context\PendingContext
     *
     * @throws \Tests\Fixtures\Exceptions\InvalidPendingCredentialException
     */
    #[\Override]
    public function fromRequest(Request $request): ?PendingContext
    {
        if ($this->invalid) {
            throw new InvalidPendingCredentialException('The pending credential does not validate.');
        }

        return $this->pending;
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Context\PendingContext  $pending
     * @return ?\SineMacula\Laravel\Mfa\Context\PendingContext
     */
    #[\Override]
    public function revalidate(PendingContext $pending): ?PendingContext
    {
        return !$this->invalid && $this->pending?->sessionId === $pending->sessionId ? $this->pending : null;
    }
}
