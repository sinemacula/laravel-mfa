<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Seams;

use SineMacula\Laravel\Mfa\Context\DefaultEventContextResolver;
use SineMacula\Laravel\Mfa\Contracts\EventContextResolver;
use SineMacula\Laravel\Mfa\Contracts\MfaEvent;
use SineMacula\Laravel\Mfa\Events\EventSubject;

/**
 * An event context resolver that records every subject it is handed and answers
 * as the default does, with the sign-in named as the session, so a test can see
 * which sign-in each event was resolved for, from the subjects or from the
 * event itself.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class RecordingEventContextResolver implements EventContextResolver
{
    /** @var list<\SineMacula\Laravel\Mfa\Events\EventSubject> The subjects handed, in order. */
    public array $subjects = [];

    /**
     * Record the subject and answer as the default does, naming the subject's
     * sign-in as the session.
     *
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
     * The sign-ins the subjects named, in order.
     *
     * @return list<?string>
     */
    public function signIns(): array
    {
        return array_map(static fn (EventSubject $subject): ?string => $subject->signInId, $this->subjects);
    }

    /**
     * The sign-ins named by the events of the class given, in order, as this
     * resolver put them in each event's context.
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
