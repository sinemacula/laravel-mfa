<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Lifecycle;

/**
 * How many records a run of pruning deleted, by kind.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class PruneResult
{
    /**
     * @param  int  $enrollments
     * @param  int  $codes
     * @param  int  $recoveryCodes
     * @param  int  $attempts
     */
    public function __construct(

        /** Abandoned enrolments. */
        public int $enrollments,

        /** Expired delivered codes. */
        public int $codes,

        /** Used or replaced recovery codes. */
        public int $recoveryCodes,

        /** Throttle rows whose window has ended. */
        public int $attempts,
    ) {}
}
