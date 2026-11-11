<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Lifecycle;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Mfa\Context\CallerContext;
use SineMacula\Laravel\Mfa\Contracts\FreshnessGate;
use SineMacula\Laravel\Mfa\Requirements\Requirement;

/**
 * Finds the session fresh and holds it to a requirement of its own, whatever
 * the package's setting says.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class FixedFreshnessGate implements FreshnessGate
{
    /**
     * @param  ?\SineMacula\Laravel\Mfa\Requirements\Requirement  $requirement
     */
    public function __construct(

        /** `null` for none. */
        private ?Requirement $requirement,
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
        return true;
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContext  $caller
     * @param  string  $operation
     * @param  ?\SineMacula\Laravel\Mfa\Requirements\Requirement  $callerRequirement
     * @return \Carbon\CarbonImmutable
     */
    #[\Override]
    public function freshUntil(CallerContext $caller, string $operation, ?Requirement $callerRequirement = null): CarbonImmutable
    {
        return CarbonImmutable::now()->addHour();
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
        return $this->requirement;
    }
}
