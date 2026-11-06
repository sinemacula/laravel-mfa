<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Contracts;

use SineMacula\Laravel\Mfa\Events\EventSubject;

/**
 * Event context resolver contract.
 *
 * The context every event carries, as an allowlist of scalar values: the
 * identity, its principal, the tenant, the session and the client (IP and user
 * agent), by id and type, never a model, a secret or a full destination, so a
 * queued listener can serialise it safely. A value it does not know is `null`.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface EventContextResolver
{
    /**
     * The context of an event about the subject: its identity, the sign-in the
     * operation was bound to when it captured one, and the client the action
     * was served to. The application is the package's own: whatever this
     * answers for it is replaced by the subject's application. A sign-in the
     * resolver cannot map to its own session leaves the session, principal and
     * tenant unknown, never filled from whichever session the process happens
     * to serve.
     *
     * @param  \SineMacula\Laravel\Mfa\Events\EventSubject  $subject
     * @return array<string, int|string|null>
     */
    public function resolve(EventSubject $subject): array;
}
