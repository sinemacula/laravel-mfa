<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Seams;

use SineMacula\Laravel\Mfa\Contracts\SessionTransition;
use SineMacula\Laravel\Mfa\Requirements\SessionChange;

/**
 * Records each change it is asked to judge and returns the completion it is
 * given.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class RecordingSessionTransition implements SessionTransition
{
    /** @var list<\SineMacula\Laravel\Mfa\Requirements\SessionChange> */
    public array $changes = [];

    /**
     * @param  ?object  $completion
     */
    public function __construct(

        /** Returned to the caller of each judgement. */
        private readonly ?object $completion = null,
    ) {}

    /**
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
     * The changes after which the session fell short.
     *
     * @return list<\SineMacula\Laravel\Mfa\Requirements\SessionChange>
     */
    public function shortfalls(): array
    {
        return array_values(array_filter($this->changes, static fn (SessionChange $change): bool => $change->outstanding !== null));
    }
}
