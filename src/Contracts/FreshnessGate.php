<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Contracts;

use SineMacula\Laravel\Mfa\Requirements\Requirement;

/**
 * Freshness gate contract.
 *
 * Whether the current session's authentication is fresh enough for a named
 * operation, asked before starting an enrolment, replacing or removing a
 * factor, generating recovery codes, or any operation the application names. It
 * is judged on the proof that satisfies the operation's requirement; where the
 * caller passes a requirement of its own, the stricter of it and the gate's own
 * setting for the operation applies. An operation with neither, or a session
 * with no record, is not fresh.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface FreshnessGate
{
    /**
     * Whether the current session is fresh for the operation.
     *
     * @param  string  $operation
     * @param  ?\SineMacula\Laravel\Mfa\Requirements\Requirement  $callerRequirement
     * @return bool
     */
    public function isFresh(string $operation, ?Requirement $callerRequirement = null): bool;
}
