<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Seams;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Mfa\Context\CallerContext;
use SineMacula\Laravel\Mfa\Contracts\FreshnessGate;
use SineMacula\Laravel\Mfa\Requirements\Requirement;

/**
 * Answers as the gate it wraps, but leaves the caller's requirement out of
 * whether the session is fresh or until when.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class CallerBlindFreshnessGate implements FreshnessGate
{
    /**
     * @param  \SineMacula\Laravel\Mfa\Contracts\FreshnessGate  $gate
     * @param  bool  $blindFresh
     * @param  bool  $blindUntil
     */
    public function __construct(

        /** Asked for every answer. */
        private FreshnessGate $gate,

        /** Whether `isFresh()` leaves it out. */
        private bool $blindFresh,

        /** Whether `freshUntil()` leaves it out. */
        private bool $blindUntil,
    ) {}

    /**
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContext  $caller
     * @param  string  $operation
     * @param  ?\SineMacula\Laravel\Mfa\Requirements\Requirement  $callerRequirement
     * @return bool
     */
    #[\Override]
    public function isFresh(CallerContext $caller, string $operation, ?Requirement $callerRequirement = null): bool
    {
        return $this->gate->isFresh($caller, $operation, $this->blindFresh ? null : $callerRequirement);
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContext  $caller
     * @param  string  $operation
     * @param  ?\SineMacula\Laravel\Mfa\Requirements\Requirement  $callerRequirement
     * @return ?\Carbon\CarbonImmutable
     */
    #[\Override]
    public function freshUntil(CallerContext $caller, string $operation, ?Requirement $callerRequirement = null): ?CarbonImmutable
    {
        return $this->gate->freshUntil($caller, $operation, $this->blindUntil ? null : $callerRequirement);
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContext  $caller
     * @param  string  $operation
     * @param  ?\SineMacula\Laravel\Mfa\Requirements\Requirement  $callerRequirement
     * @return ?\SineMacula\Laravel\Mfa\Requirements\Requirement
     */
    #[\Override]
    public function requirement(CallerContext $caller, string $operation, ?Requirement $callerRequirement = null): ?Requirement
    {
        return $this->gate->requirement($caller, $operation, $callerRequirement);
    }
}
