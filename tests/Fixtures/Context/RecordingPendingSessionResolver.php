<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Context;

use Illuminate\Http\Request;
use SineMacula\Laravel\Mfa\Context\PendingContext;
use SineMacula\Laravel\Mfa\Contracts\PendingSessionResolver;

/**
 * Answers the same pending session for every request and records the credential
 * of each one it revalidates.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class RecordingPendingSessionResolver implements PendingSessionResolver
{
    /** @var list<?string> */
    public array $revalidated = [];

    /**
     * @param  \SineMacula\Laravel\Mfa\Context\PendingContext  $pending
     */
    public function __construct(

        /** Answered for every request. */
        private readonly PendingContext $pending,
    ) {}

    /**
     * @param  \Illuminate\Http\Request  $request
     * @return \SineMacula\Laravel\Mfa\Context\PendingContext
     */
    #[\Override]
    public function fromRequest(Request $request): PendingContext
    {
        return $this->pending;
    }

    /**
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
