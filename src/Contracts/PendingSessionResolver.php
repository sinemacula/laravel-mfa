<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Contracts;

use Illuminate\Http\Request;
use SineMacula\Laravel\Mfa\Context\PendingContext;

/**
 * Resolves a pending session from a credential the authentication layer has
 * already validated; the package never parses one itself.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface PendingSessionResolver
{
    /**
     * `null` only when the request carries no pending credential; an invalid
     * one throws so the request is refused.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return ?\SineMacula\Laravel\Mfa\Context\PendingContext
     *
     * @throws \RuntimeException
     */
    public function fromRequest(Request $request): ?PendingContext;

    /**
     * The pending session as it stands now, or `null` when it no longer stands
     * or cannot be validated again, never the snapshot given back.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\PendingContext  $pending
     * @return ?\SineMacula\Laravel\Mfa\Context\PendingContext
     */
    public function revalidate(PendingContext $pending): ?PendingContext;
}
