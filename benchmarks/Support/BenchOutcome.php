<?php

declare(strict_types = 1);

namespace Benchmarks\Support;

/**
 * Proof, at set-up, that a benchmarked path reaches the outcome it is named
 * for, so a fixture that drifts fails the run instead of timing a refusal in
 * the path's place.
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
     * Throw unless the path reached its outcome.
     *
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
