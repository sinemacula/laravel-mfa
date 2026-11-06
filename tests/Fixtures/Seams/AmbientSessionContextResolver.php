<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Seams;

use SineMacula\Laravel\Mfa\Contracts\EventContextResolver;
use SineMacula\Laravel\Mfa\Events\EventSubject;

/**
 * An event context resolver that names the session the process is serving,
 * whatever sign-in the subject names, as one that read the current session
 * would: for proving the contract kit rejects it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class AmbientSessionContextResolver implements EventContextResolver
{
    /** @var string The session the process is serving. */
    public const string SESSION = 'served-session';

    /**
     * The context, naming the session being served and its tenant.
     *
     * @param  \SineMacula\Laravel\Mfa\Events\EventSubject  $subject
     * @return array<string, int|string|null>
     */
    #[\Override]
    public function resolve(EventSubject $subject): array
    {
        return ['session_id' => self::SESSION, 'tenant_id' => 'served-tenant'];
    }
}
