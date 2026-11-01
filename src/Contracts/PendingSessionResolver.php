<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Contracts;

use Illuminate\Http\Request;
use SineMacula\Laravel\Mfa\Context\PendingContext;

/**
 * Pending session resolver contract.
 *
 * Resolves the request's pending session, a sign-in still owing a requirement,
 * from a pending credential the authentication layer has already validated: the
 * identity, the application, the session's public id, the first factor's proof,
 * the outstanding requirement, and the actions the credential allows. This
 * package never parses or validates a pending credential itself, and serves a
 * pending session only the actions it allows.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface PendingSessionResolver
{
    /**
     * The request's pending session, or `null` when it carries none.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return ?\SineMacula\Laravel\Mfa\Context\PendingContext
     */
    public function resolve(Request $request): ?PendingContext;
}
