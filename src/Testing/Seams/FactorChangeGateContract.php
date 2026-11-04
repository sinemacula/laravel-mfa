<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Testing\Seams;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Assert;
use SineMacula\Laravel\Mfa\Contracts\FactorChangeGate;
use SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException;
use SineMacula\Laravel\Mfa\Requirements\FactorChangeRequest;

/**
 * What every `FactorChangeGate` must guarantee, as assertions: a change from a
 * session fresh enough for it is allowed, and a grant it allows ends in the
 * future; a change from a session that is not is refused by throwing an
 * `OperationRefusedException`, never by returning; a factor never authorises
 * its own removal; and the requirement the application configures binds it.
 *
 * Each assertion takes the request as the test arranged it: what makes a
 * session fresh or not is the implementation's.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
final class FactorChangeGateContract
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * A change from a session fresh enough for it is allowed, and a grant ends
     * in the future.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\FactorChangeGate  $gate
     * @param  \SineMacula\Laravel\Mfa\Requirements\FactorChangeRequest  $fresh
     * @return void
     */
    public static function assertAFreshChangeIsAllowed(FactorChangeGate $gate, FactorChangeRequest $fresh): void
    {
        $until = $gate->authorize($fresh);

        if (!$fresh->change->isGrant()) {
            return;
        }

        Assert::assertNotNull($until, 'A grant the gate allows must have an end.');
        Assert::assertTrue($until->greaterThan(CarbonImmutable::now()), 'A grant the gate allows must end in the future.');
    }

    /**
     * A change from a session that is not fresh enough for it is refused by
     * throwing an `OperationRefusedException`.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\FactorChangeGate  $gate
     * @param  \SineMacula\Laravel\Mfa\Requirements\FactorChangeRequest  $stale
     * @param  string  $message
     * @return void
     */
    public static function assertAStaleChangeIsRefused(
        FactorChangeGate $gate,
        FactorChangeRequest $stale,
        string $message = 'A change from a session that is not fresh enough must be refused by throwing.',
    ): void {
        $outcome = null;

        try {
            $gate->authorize($stale);
        } catch (\Throwable $exception) {
            $outcome = $exception;
        }

        Assert::assertInstanceOf(OperationRefusedException::class, $outcome, $message);
    }

    /**
     * A removal from a session whose only step-up was made with the factor
     * being removed, while the identity has another confirmed factor, is
     * refused.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\FactorChangeGate  $gate
     * @param  \SineMacula\Laravel\Mfa\Requirements\FactorChangeRequest  $removal
     * @return void
     */
    public static function assertAFactorNeverAuthorizesItsOwnRemoval(FactorChangeGate $gate, FactorChangeRequest $removal): void
    {
        self::assertAStaleChangeIsRefused($gate, $removal, 'A step-up made with the factor being removed must not authorise its removal.');
    }

    /**
     * A change from a session fresh by the gate's own policy, but not by the
     * requirement the request carries, is refused.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\FactorChangeGate  $gate
     * @param  \SineMacula\Laravel\Mfa\Requirements\FactorChangeRequest  $stricter
     * @return void
     */
    public static function assertTheConfiguredRequirementBinds(FactorChangeGate $gate, FactorChangeRequest $stricter): void
    {
        self::assertAStaleChangeIsRefused($gate, $stricter, 'The requirement the application configures must bind the gate.');
    }
}
