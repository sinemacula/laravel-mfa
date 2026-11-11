<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Context;

use Illuminate\Container\Container;
use Illuminate\Http\Request;
use SineMacula\Laravel\Mfa\Context\PendingContext;
use SineMacula\Laravel\Mfa\Contracts\PendingSessionResolver;

/**
 * Answers what the request it is handed holds, so a test can tell which request
 * was read.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class RequestAttributePendingSessionResolver implements PendingSessionResolver
{
    /** @var string */
    public const string ATTRIBUTE = 'pending_session';

    /**
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
     * Reads the request being served, so a test can change the attribute to
     * revoke or change the session meanwhile.
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
