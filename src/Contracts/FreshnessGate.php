<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Contracts;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Mfa\Context\CallerContext;
use SineMacula\Laravel\Mfa\Requirements\Requirement;

/**
 * Whether the session is fresh enough for an operation; an adapter applies the
 * stricter of the caller's requirement and its own, keeping no state.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface FreshnessGate
{
    /**
     * An unknown operation or a session with no record is not fresh; a caller's
     * part with no maximum age, or over 86400 seconds, throws.
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
     * The stricter of the gate's setting and the caller's, either alone when
     * the other is absent, or `null` with neither.
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
     * When the session stops being fresh on its current proofs, or `null` when
     * it is not fresh or the gate cannot say; never in the past.
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
