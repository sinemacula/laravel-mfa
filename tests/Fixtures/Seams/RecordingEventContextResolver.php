<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Seams;

use SineMacula\Laravel\Mfa\Context\DefaultEventContextResolver;
use SineMacula\Laravel\Mfa\Contracts\EventContextResolver;
use SineMacula\Laravel\Mfa\Contracts\MfaEvent;
use SineMacula\Laravel\Mfa\Events\EventSubject;

/**
 * Records every subject and answers as the default does with the sign-in as the
 * session, so a test can see which sign-in each event was resolved for.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class RecordingEventContextResolver implements EventContextResolver
{
    /** @var list<\SineMacula\Laravel\Mfa\Events\EventSubject> */
    public array $subjects = [];

    /**
     * @param  \SineMacula\Laravel\Mfa\Events\EventSubject  $subject
     * @return array<string, int|string|null>
     */
    #[\Override]
    public function resolve(EventSubject $subject): array
    {
        $this->subjects[] = $subject;

        return [...(new DefaultEventContextResolver)->resolve($subject), 'session_id' => $subject->signInId];
    }

    /**
     * @return list<?string>
     */
    public function signIns(): array
    {
        return array_map(static fn (EventSubject $subject): ?string => $subject->signInId, $this->subjects);
    }

    /**
     * The sign-ins this resolver put in the context of each event of the class.
     *
     * @param  list<\SineMacula\Laravel\Mfa\Contracts\MfaEvent>  $events
     * @param  class-string<\SineMacula\Laravel\Mfa\Contracts\MfaEvent>  $class
     * @return list<int|string|null>
     */
    public static function signInsOf(array $events, string $class): array
    {
        $named = array_filter($events, static fn (MfaEvent $event): bool => $event instanceof $class);

        return array_values(array_map(static fn (MfaEvent $event): int|string|null => $event->context()['session_id'] ?? null, $named));
    }
}
