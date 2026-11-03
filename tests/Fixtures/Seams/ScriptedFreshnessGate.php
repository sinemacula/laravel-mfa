<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Seams;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Mfa\Contracts\FreshnessGate;
use SineMacula\Laravel\Mfa\Requirements\Requirement;

/**
 * A freshness gate that answers every operation as it is told, whether fresh
 * and until when, each answer on its own, so a gate whose answers disagree can
 * be given to the contract kit.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ScriptedFreshnessGate implements FreshnessGate
{
    /**
     * Constructor.
     *
     * @param  bool  $fresh
     * @param  ?\Carbon\CarbonImmutable  $until
     */
    public function __construct(

        /** Whether every operation is fresh. */
        private bool $fresh,

        /** The deadline of every operation, or `null` for none. */
        private ?CarbonImmutable $until,
    ) {}

    /**
     * Fresh as told.
     *
     * @param  string  $operation
     * @param  ?\SineMacula\Laravel\Mfa\Requirements\Requirement  $callerRequirement
     * @return bool
     */
    #[\Override]
    public function isFresh(string $operation, ?Requirement $callerRequirement = null): bool
    {
        return $this->fresh;
    }

    /**
     * The deadline as told.
     *
     * @param  string  $operation
     * @param  ?\SineMacula\Laravel\Mfa\Requirements\Requirement  $callerRequirement
     * @return ?\Carbon\CarbonImmutable
     */
    #[\Override]
    public function freshUntil(string $operation, ?Requirement $callerRequirement = null): ?CarbonImmutable
    {
        return $this->until;
    }

    /**
     * No requirement of its own.
     *
     * @param  string  $operation
     * @param  ?\SineMacula\Laravel\Mfa\Requirements\Requirement  $callerRequirement
     * @return ?\SineMacula\Laravel\Mfa\Requirements\Requirement
     */
    #[\Override]
    public function requirement(string $operation, ?Requirement $callerRequirement = null): ?Requirement
    {
        return $callerRequirement;
    }
}
