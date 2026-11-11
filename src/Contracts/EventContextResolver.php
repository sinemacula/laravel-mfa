<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Contracts;

use SineMacula\Laravel\Mfa\Events\EventSubject;

/**
 * The scalar context every event carries, by id and type, never a model, secret
 * or full destination, so a queued listener can serialise it.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface EventContextResolver
{
    /**
     * Context of an event about the subject; a sign-in it cannot map to its own
     * session leaves the session, principal and tenant `null`.
     *
     * @param  \SineMacula\Laravel\Mfa\Events\EventSubject  $subject
     * @return array<string, int|string|null>
     */
    public function resolve(EventSubject $subject): array;
}
