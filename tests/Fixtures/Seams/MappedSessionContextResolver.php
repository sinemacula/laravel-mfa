<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Seams;

use SineMacula\Laravel\Mfa\Contracts\EventContextResolver;
use SineMacula\Laravel\Mfa\Events\EventSubject;

/**
 * Names the session of the one sign-in it knows, and nothing for any other.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class MappedSessionContextResolver implements EventContextResolver
{
    /** @var string */
    public const string APPLICATION = 'web';

    /** @var string */
    public const string SIGN_IN = 'sign-in-1';

    /**
     * @param  \SineMacula\Laravel\Mfa\Events\EventSubject  $subject
     * @return array<string, int|string|null>
     */
    #[\Override]
    public function resolve(EventSubject $subject): array
    {
        $known = $subject->application === self::APPLICATION && $subject->signInId === self::SIGN_IN;

        return ['session_id' => $known ? 'session-1' : null];
    }
}
