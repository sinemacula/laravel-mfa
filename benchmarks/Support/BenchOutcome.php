<?php

declare(strict_types = 1);

namespace Benchmarks\Support;

/**
 * Fails the run when a drifted fixture would time a refusal instead of the
 * path.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class BenchOutcome
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * @param  string  $path
     * @param  bool  $reached
     * @return void
     *
     * @throws \LogicException
     */
    public static function assert(string $path, bool $reached): void
    {
        if (!$reached) {
            throw new \LogicException(sprintf('The %s benchmark does not reach the outcome it measures; fix its fixtures before timing it.', $path));
        }
    }
}
