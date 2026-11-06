<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Seams;

use SineMacula\Laravel\Mfa\Context\DefaultEventContextResolver;
use SineMacula\Laravel\Mfa\Contracts\EventContextResolver;
use SineMacula\Laravel\Mfa\Events\EventSubject;

/**
 * An event context resolver that records every subject it is handed and answers
 * as the default does, so a test can see which sign-in each event was resolved
 * for.
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
     * Record the subject and answer as the default does.
     *
     * @param  \SineMacula\Laravel\Mfa\Events\EventSubject  $subject
     * @return array<string, int|string|null>
     */
    #[\Override]
    public function resolve(EventSubject $subject): array
    {
        $this->subjects[] = $subject;

        return (new DefaultEventContextResolver)->resolve($subject);
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
}
