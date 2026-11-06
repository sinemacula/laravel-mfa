<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Context;

use Illuminate\Http\Request;
use SineMacula\Laravel\Mfa\Context\PendingContext;
use SineMacula\Laravel\Mfa\Contracts\PendingSessionResolver;

/**
 * A pending session resolver that answers the same pending session for every
 * request, and records the credential of each pending session it is asked to
 * read again.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class RecordingPendingSessionResolver implements PendingSessionResolver
{
    /** @var list<?string> The credential of each pending session read again, in order. */
    public array $revalidated = [];

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\PendingContext  $pending
     */
    public function __construct(

        /** The pending session answered. */
        private readonly PendingContext $pending,
    ) {}

    /**
     * The fixed pending session.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \SineMacula\Laravel\Mfa\Context\PendingContext
     */
    #[\Override]
    public function fromRequest(Request $request): PendingContext
    {
        return $this->pending;
    }

    /**
     * Record the credential presented, and answer the pending session again.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\PendingContext  $pending
     * @return \SineMacula\Laravel\Mfa\Context\PendingContext
     */
    #[\Override]
    public function revalidate(PendingContext $pending): PendingContext
    {
        $this->revalidated[] = $pending->credential();

        return $this->pending;
    }
}
