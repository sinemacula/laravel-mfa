<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Lifecycle;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Mfa\Contracts\FreshnessGate;
use SineMacula\Laravel\Mfa\Requirements\Requirement;

/**
 * A freshness gate an adapter might bind: it finds the session fresh, and holds
 * it to a requirement of its own whatever the package's setting says.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class FixedFreshnessGate implements FreshnessGate
{
    /**
     * Constructor.
     *
     * @param  ?\SineMacula\Laravel\Mfa\Requirements\Requirement  $requirement
     */
    public function __construct(

        /** The requirement the gate holds a session to, or `null` for none. */
        private ?Requirement $requirement,
    ) {}

    /**
     * Fresh.
     *
     * @param  string  $operation
     * @param  ?\SineMacula\Laravel\Mfa\Requirements\Requirement  $callerRequirement
     * @return bool
     */
    #[\Override]
    public function isFresh(string $operation, ?Requirement $callerRequirement = null): bool
    {
        return true;
    }

    /**
     * An hour on.
     *
     * @param  string  $operation
     * @param  ?\SineMacula\Laravel\Mfa\Requirements\Requirement  $callerRequirement
     * @return \Carbon\CarbonImmutable
     */
    #[\Override]
    public function freshUntil(string $operation, ?Requirement $callerRequirement = null): CarbonImmutable
    {
        return CarbonImmutable::now()->addHour();
    }

    /**
     * The fixed requirement.
     *
     * @param  string  $operation
     * @param  ?\SineMacula\Laravel\Mfa\Requirements\Requirement  $callerRequirement
     * @return ?\SineMacula\Laravel\Mfa\Requirements\Requirement
     */
    #[\Override]
    public function requirement(string $operation, ?Requirement $callerRequirement = null): ?Requirement
    {
        return $this->requirement;
    }
}
