<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Testing\Seams;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Assert;
use SineMacula\Laravel\Mfa\Contracts\FactorChangeGate;
use SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException;
use SineMacula\Laravel\Mfa\Requirements\FactorChangeRequest;

/**
 * What every `FactorChangeGate` must guarantee: a fresh change is allowed with
 * a future grant, a stale one throws `OperationRefusedException`, a factor
 * never authorises its own removal, and the configured requirement binds. The
 * test arranges what makes a session fresh.
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
     * The grant must end in the future.
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
     * `$removal`'s only step-up used the factor being removed, and the identity
     * has another confirmed factor.
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
     * `$stricter` is fresh by the gate's own policy but not by the requirement
     * it carries.
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
