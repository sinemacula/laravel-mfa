<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Contracts;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Mfa\Context\CallerContext;
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
 * `freshUntil()` asks the same question and says how long the answer lasts, so
 * what an answer authorises can live no longer than the proofs it rests on: an
 * enrolment grant stores it once and never asks again, since a later proof must
 * not bring an expired grant back. A gate that cannot say answers `null`, and
 * what depends on it is refused.
 *
 * `requirement()` says what the gate holds the session to, so a caller that
 * must judge that requirement on only some of the session's proofs (removing a
 * factor, on the proofs made without it) judges the gate's own, stricter one
 * and not merely the package's setting. A gate with no requirement for the
 * operation answers `null`, and what depends on it is refused.
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
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContext  $caller
     * @param  string  $operation
     * @param  ?\SineMacula\Laravel\Mfa\Requirements\Requirement  $callerRequirement
     * @return bool
     *
     * @throws \InvalidArgumentException
     */
    public function isFresh(CallerContext $caller, string $operation, ?Requirement $callerRequirement = null): bool;

    /**
     * The requirement the gate holds the current session to for the operation:
     * the stricter of its own setting and the caller's, either alone when the
     * other is absent, and `null` with neither.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContext  $caller
     * @param  string  $operation
     * @param  ?\SineMacula\Laravel\Mfa\Requirements\Requirement  $callerRequirement
     * @return ?\SineMacula\Laravel\Mfa\Requirements\Requirement
     *
     * @throws \InvalidArgumentException
     */
    public function requirement(CallerContext $caller, string $operation, ?Requirement $callerRequirement = null): ?Requirement;

    /**
     * The instant the current session stops being fresh for the operation on
     * the proofs it holds now, or `null` when it is not fresh, or the gate
     * cannot say. An answer that is not `null` implies `isFresh()` is `true`,
     * and is never in the past.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContext  $caller
     * @param  string  $operation
     * @param  ?\SineMacula\Laravel\Mfa\Requirements\Requirement  $callerRequirement
     * @return ?\Carbon\CarbonImmutable
     *
     * @throws \InvalidArgumentException
     */
    public function freshUntil(CallerContext $caller, string $operation, ?Requirement $callerRequirement = null): ?CarbonImmutable;
}
