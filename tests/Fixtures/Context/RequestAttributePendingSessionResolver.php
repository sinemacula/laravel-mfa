<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Context;

use Illuminate\Container\Container;
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
    public function fromRequest(Request $request): ?PendingContext
    {
        $pending = $request->attributes->get(self::ATTRIBUTE);

        return $pending instanceof PendingContext ? $pending : null;
    }

    /**
     * The pending session the request being served carries now, when it is
     * still the one given: a test changes the attribute to stand for a session
     * revoked or changed meanwhile.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\PendingContext  $pending
     * @return ?\SineMacula\Laravel\Mfa\Context\PendingContext
     */
    #[\Override]
    public function revalidate(PendingContext $pending): ?PendingContext
    {
        $now = Container::getInstance()->make('request')->attributes->get(self::ATTRIBUTE);

        return $now instanceof PendingContext && $now->sessionId === $pending->sessionId ? $now : null;
    }
}
