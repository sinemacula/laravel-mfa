<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Context;

use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;

/**
 * Who an action is serving: a person, either the identity of a pending session
 * whose credential allows what the action does, or an identity on an active
 * session, with the application it acts on and its client.
 *
 * It is resolved from the action's `CallerContext` (see
 * `CallerContextResolver`) and holds nothing beyond it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class Caller
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  ?\SineMacula\Laravel\Mfa\Context\PendingContext  $pending
     * @param  string  $application
     * @param  \SineMacula\Laravel\Mfa\Context\ClientContext  $client
     */
    public function __construct(

        /** The person being served. */
        public MultiFactorAuthenticatable $identity,

        /** The pending session the person is served on, or `null` for an active one. */
        public ?PendingContext $pending,

        /** The application the person is served on: the pending session's, for a pending one. */
        public string $application,

        /** The client the person is served through. */
        public ClientContext $client = new ClientContext,
    ) {}

    /**
     * The caller as the context a seam is handed.
     *
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
