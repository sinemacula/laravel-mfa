<?php

declare(strict_types = 1);

namespace Tests\Integration\Process\Fixtures;

/**
 * What each job a worker ran saw, kept on the application for the test to read.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class JobObservations
{
    /** @var list<array{job: string, identity: mixed, factors: list<string>, proofs: int, changed: bool}> What each job saw, oldest first. */
    public array $seen = [];
}
