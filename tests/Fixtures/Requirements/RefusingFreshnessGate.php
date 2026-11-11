<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Requirements;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Mfa\Context\CallerContext;
use SineMacula\Laravel\Mfa\Contracts\FreshnessGate;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException;
use SineMacula\Laravel\Mfa\Requirements\Requirement;

/**
 * Fresh until the numbered read, which it refuses with its own exception. The
 * first read is made before the lock, the second under it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class RefusingFreshnessGate implements FreshnessGate
{
    /** @var int */
    private int $reads = 0;

    /**
     * @param  int  $refuseOnRead
     */
    public function __construct(

        /** The read refused, `0` for none. */
        private readonly int $refuseOnRead,
    ) {}

    /**
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContext  $caller
     * @param  string  $operation
     * @param  ?\SineMacula\Laravel\Mfa\Requirements\Requirement  $callerRequirement
     * @return bool
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     */
    #[\Override]
    public function isFresh(CallerContext $caller, string $operation, ?Requirement $callerRequirement = null): bool
    {
        if (++$this->reads === $this->refuseOnRead) {
            throw new OperationRefusedException(FailureReason::NOT_ACCEPTED, 'The freshness gate refused.');
        }

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
        return $callerRequirement;
    }
}
