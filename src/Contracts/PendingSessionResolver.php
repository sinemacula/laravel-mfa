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
 * `fromRequest()` is the edge that reads the credential a request presents, for
 * `Context\CallerContext::fromRequest()`; no action calls it. `revalidate()` is
 * asked under the identity's lock, with the pending session the caller was
 * served, so a credential revoked or changed meanwhile refuses the action. It
 * reads no request: a resolver that must see the credential again keeps it on
 * the `PendingContext` it returns, as `credential()`.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface PendingSessionResolver
{
    /**
     * The request's pending session, or `null` only when the request carries no
     * pending credential. A credential that does not validate is reported by
     * throwing, never by answering `null`, so the request is refused rather
     * than served as the guard's user.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return ?\SineMacula\Laravel\Mfa\Context\PendingContext
     *
     * @throws \RuntimeException
     */
    public function fromRequest(Request $request): ?PendingContext;

    /**
     * The pending session as it stands now, read again from the credential the
     * caller presented, or `null` when it no longer stands: expired, revoked,
     * completed, or no longer this session. It may answer the session with its
     * actions, requirement and proofs as they stand now. A session it cannot
     * validate again, such as one whose credential it kept none of, is `null`,
     * never the snapshot given back.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\PendingContext  $pending
     * @return ?\SineMacula\Laravel\Mfa\Context\PendingContext
     */
    public function revalidate(PendingContext $pending): ?PendingContext;
}
