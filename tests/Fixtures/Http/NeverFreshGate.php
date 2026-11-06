<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Http;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Mfa\Context\CallerContext;
use SineMacula\Laravel\Mfa\Contracts\FreshnessGate;
use SineMacula\Laravel\Mfa\Requirements\Requirement;

/**
 * A freshness gate an adapter might bind that finds no session fresh, whatever
 * its proofs show, and holds it to a requirement of its own.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class NeverFreshGate implements FreshnessGate
{
    /**
     * Constructor.
     *
     * @param  ?\SineMacula\Laravel\Mfa\Requirements\Requirement  $requirement
     */
    public function __construct(

        /** The requirement the gate holds a session to, or `null` for none. */
        private ?Requirement $requirement = null,
    ) {}

    /**
     * Never fresh.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContext  $caller
     * @param  string  $operation
     * @param  ?\SineMacula\Laravel\Mfa\Requirements\Requirement  $callerRequirement
     * @return bool
     */
    #[\Override]
    public function isFresh(CallerContext $caller, string $operation, ?Requirement $callerRequirement = null): bool
    {
        return false;
    }

    /**
     * No deadline.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContext  $caller
     * @param  string  $operation
     * @param  ?\SineMacula\Laravel\Mfa\Requirements\Requirement  $callerRequirement
     * @return ?\Carbon\CarbonImmutable
     */
    #[\Override]
    public function freshUntil(CallerContext $caller, string $operation, ?Requirement $callerRequirement = null): ?CarbonImmutable
    {
        return null;
    }

    /**
     * The fixed requirement.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContext  $caller
     * @param  string  $operation
     * @param  ?\SineMacula\Laravel\Mfa\Requirements\Requirement  $callerRequirement
     * @return ?\SineMacula\Laravel\Mfa\Requirements\Requirement
     */
    #[\Override]
    public function requirement(CallerContext $caller, string $operation, ?Requirement $callerRequirement = null): ?Requirement
    {
        return $this->requirement;
    }
}
