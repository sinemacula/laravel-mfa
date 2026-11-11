<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Context;

use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;

/**
 * The person an action serves, on a pending or active session, resolved from
 * the action's `CallerContext` and holding nothing beyond it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class Caller
{
    /**
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  ?\SineMacula\Laravel\Mfa\Context\PendingContext  $pending
     * @param  string  $application
     * @param  \SineMacula\Laravel\Mfa\Context\ClientContext  $client
     */
    public function __construct(

        /** The person served. */
        public MultiFactorAuthenticatable $identity,

        /** `null` on an active session. */
        public ?PendingContext $pending,

        /** The pending session's application, when pending. */
        public string $application,

        /** The client served through. */
        public ClientContext $client = new ClientContext,
    ) {}

    /**
     * @return \SineMacula\Laravel\Mfa\Context\CallerContext
     *
     * @throws \InvalidArgumentException
     */
    public function context(): CallerContext
    {
        return $this->pending === null
            ? CallerContext::forIdentity($this->identity, $this->application, $this->client)
            : CallerContext::forPending($this->pending, $this->client);
    }
}
