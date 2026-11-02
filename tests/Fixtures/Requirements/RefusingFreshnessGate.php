<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Requirements;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Mfa\Contracts\FreshnessGate;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException;
use SineMacula\Laravel\Mfa\Requirements\Requirement;

/**
 * A freshness gate that is fresh until the read named, which it refuses with
 * its own exception, as a gate of an application's may: the first read is made
 * before the lock, the second under it. Read `0` refuses none, so it is always
 * fresh.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class RefusingFreshnessGate implements FreshnessGate
{
    /** @var int How many times the gate was asked. */
    private int $reads = 0;

    /**
     * Constructor.
     *
     * @param  int  $refuseOnRead
     */
    public function __construct(

        /** The read refused, `0` for none. */
        private readonly int $refuseOnRead,
    ) {}

    /**
     * Fresh, unless this read is refused.
     *
     * @param  string  $operation
     * @param  ?\SineMacula\Laravel\Mfa\Requirements\Requirement  $callerRequirement
     * @return bool
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     */
    #[\Override]
    public function isFresh(string $operation, ?Requirement $callerRequirement = null): bool
    {
        if (++$this->reads === $this->refuseOnRead) {
            throw new OperationRefusedException(FailureReason::NOT_ACCEPTED, 'The freshness gate refused.');
        }

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
     * The caller's requirement, unchanged.
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
