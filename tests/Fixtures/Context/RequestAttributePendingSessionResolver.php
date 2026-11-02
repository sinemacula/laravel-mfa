<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Context;

use Illuminate\Http\Request;
use SineMacula\Laravel\Mfa\Context\PendingContext;
use SineMacula\Laravel\Mfa\Contracts\PendingSessionResolver;

/**
 * A pending session resolver that answers what the request it is handed holds,
 * so a test can tell which request was read.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class RequestAttributePendingSessionResolver implements PendingSessionResolver
{
    /** @var string The request attribute holding the pending session. */
    public const string ATTRIBUTE = 'pending_session';

    /**
     * The pending session the request holds, if any.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return ?\SineMacula\Laravel\Mfa\Context\PendingContext
     */
    #[\Override]
    public function resolve(Request $request): ?PendingContext
    {
        $pending = $request->attributes->get(self::ATTRIBUTE);

        return $pending instanceof PendingContext ? $pending : null;
    }
}
