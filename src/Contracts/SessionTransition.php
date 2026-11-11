<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Contracts;

use SineMacula\Laravel\Mfa\Requirements\SessionChange;

/**
 * Judges the identity's current session again after a change to its factors,
 * inside the identity's transaction; lock any session row of your own last.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface SessionTransition
{
    /**
     * Return what the caller receives, or `null`; throw rather than return so
     * the change rolls back, and release nothing before it commits.
     *
     * @param  \SineMacula\Laravel\Mfa\Requirements\SessionChange  $change
     * @return ?object
     *
     * @throws \RuntimeException
     */
    public function factorChanged(SessionChange $change): ?object;
}
