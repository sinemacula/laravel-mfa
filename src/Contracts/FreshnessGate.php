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
 * is judged on the session's recorded proofs, each part of the requirement on
 * the newest proof that meets it within its maximum age, so a fresh weaker
 * proof never refreshes an old stronger one, a fresh first factor never stands
 * in for an additional factor, and refreshing the session renews nothing.
 *
 * Where the caller passes a requirement of its own, the stricter of it and the
 * gate's own setting for the operation applies, either alone when the other is
 * absent. An operation with neither, a name that is not an operation's
 * (lower-case segments of letters, digits and underscores, each starting with a
 * letter, separated by dots), or a session with no record, is not fresh. A
 * caller's requirement that asks for nothing adds nothing; one with a part that
 * carries no maximum age, or one longer than 86400 seconds, is refused with an
 * `InvalidArgumentException`.
 *
 * The package passes its own setting for the operation as part of the caller's
 * requirement, so a gate bound in its place (an adapter over an authentication
 * layer's freshness check) must apply the stricter of that and its own setting,
 * never either alone, and keep no state between calls.
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
     *
     * @throws \InvalidArgumentException
     */
    public function isFresh(string $operation, ?Requirement $callerRequirement = null): bool;
}
