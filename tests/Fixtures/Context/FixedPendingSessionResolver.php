<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Context;

use Illuminate\Http\Request;
use SineMacula\Laravel\Mfa\Context\PendingContext;
use SineMacula\Laravel\Mfa\Contracts\PendingSessionResolver;
use Tests\Fixtures\Exceptions\InvalidPendingCredentialException;

/**
 * A pending session resolver that answers the same pending session, or none,
 * for every request, or refuses every request as carrying a pending credential
 * that does not validate.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class FixedPendingSessionResolver implements PendingSessionResolver
{
    /**
     * Constructor.
     *
     * @param  ?\SineMacula\Laravel\Mfa\Context\PendingContext  $pending
     * @param  bool  $invalid
     */
    public function __construct(

        /** The pending session answered, or `null` for none. */
        private ?PendingContext $pending = null,

        /** Whether every request carries a credential that does not validate. */
        private bool $invalid = false,
    ) {}

    /**
     * The fixed pending session, or a refusal.
     *
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
     * The fixed pending session again, when it is still the one given and the
     * credential still validates; otherwise none.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\PendingContext  $pending
     * @return ?\SineMacula\Laravel\Mfa\Context\PendingContext
     */
    #[\Override]
    public function revalidate(PendingContext $pending): ?PendingContext
    {
        return !$this->invalid && $this->pending?->sessionId === $pending->sessionId ? $this->pending : null;
    }
}
