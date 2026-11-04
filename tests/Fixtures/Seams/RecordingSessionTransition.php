<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Seams;

use SineMacula\Laravel\Mfa\Contracts\SessionTransition;
use SineMacula\Laravel\Mfa\Requirements\SessionChange;

/**
 * A session transition that records each change it is asked to judge the
 * session again after, and returns the completion it is given.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class RecordingSessionTransition implements SessionTransition
{
    /** @var list<\SineMacula\Laravel\Mfa\Requirements\SessionChange> Each change judged, in order. */
    public array $changes = [];

    /**
     * Constructor.
     *
     * @param  ?object  $completion
     */
    public function __construct(

        /** What each judgement returns for the caller. */
        private readonly ?object $completion = null,
    ) {}

    /**
     * Record the change, and return the completion.
     *
     * @param  \SineMacula\Laravel\Mfa\Requirements\SessionChange  $change
     * @return ?object
     */
    #[\Override]
    public function factorChanged(SessionChange $change): ?object
    {
        $this->changes[] = $change;

        return $this->completion;
    }

    /**
     * The changes judged that the package found the session short after.
     *
     * @return list<\SineMacula\Laravel\Mfa\Requirements\SessionChange>
     */
    public function shortfalls(): array
    {
        return array_values(array_filter($this->changes, static fn (SessionChange $change): bool => $change->outstanding !== null));
    }
}
