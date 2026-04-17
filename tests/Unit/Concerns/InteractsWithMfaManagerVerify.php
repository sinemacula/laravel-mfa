<?php

declare(strict_types = 1);

namespace Tests\Unit\Concerns;

use SineMacula\Laravel\Mfa\Contracts\FactorDriver;
use SineMacula\Laravel\Mfa\MfaManager;

/**
 * Shared scaffolding for the `MfaManager::verify()` test family.
 *
 * Centralises driver stubbing and manager resolution so the verify
 * orchestration tests and the `classifyFailure()` reason-mapping tests can live
 * in separate files without duplicating helpers.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 *
 * @internal
 */
trait InteractsWithMfaManagerVerify
{
    /**
     * Register a stub driver under the given name on the MFA manager.
     *
     * @param  string  $name
     * @param  \SineMacula\Laravel\Mfa\Contracts\FactorDriver  $driver
     * @return void
     */
    protected function stubDriver(string $name, FactorDriver $driver): void
    {
        $this->manager()->extend($name, fn (): FactorDriver => $driver);
    }

    /**
     * Resolve the package's MFA manager from the container.
     *
     * @return \SineMacula\Laravel\Mfa\MfaManager
     */
    protected function manager(): MfaManager
    {
        $manager = $this->container()->make('mfa');
        \PHPUnit\Framework\Assert::assertInstanceOf(MfaManager::class, $manager);

        return $manager;
    }
}
