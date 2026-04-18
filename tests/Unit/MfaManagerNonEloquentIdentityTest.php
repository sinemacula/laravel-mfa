<?php

declare(strict_types = 1);

namespace Tests\Unit;

use Illuminate\Support\Facades\Auth;
use PHPUnit\Framework\Assert;
use SineMacula\Laravel\Mfa\Contracts\FactorDriver;
use SineMacula\Laravel\Mfa\Exceptions\FactorOwnershipMismatchException;
use SineMacula\Laravel\Mfa\MfaManager;
use SineMacula\Laravel\Mfa\Models\Factor;
use Tests\Fixtures\InMemoryFactor;
use Tests\Fixtures\NonEloquentIdentity;

/**
 * Coverage for the manager's FQCN-fallback paths.
 *
 * `assertFactorOwnership()`, `getCachePrefix()`, and `issueBackupCodes()` all
 * branch on `$identity instanceof Model` — Eloquent identities use
 * `getMorphClass()`, non-Eloquent identities fall back to a strict FQCN
 * comparison. The shipped test identities (`TestUser`, `SecondaryUser`,
 * `NonScalarIdentifierUser`) are all Eloquent, so a dedicated non-Eloquent
 * fixture is needed to drive the FQCN branches and keep coverage at 100%.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 *
 * @internal
 */
final class MfaManagerNonEloquentIdentityTest extends MfaManagerTestCase
{
    /**
     * Tear down Mockery expectations between test cases.
     *
     * @return void
     */
    protected function tearDown(): void
    {
        if (class_exists(\Mockery::class)) {
            \Mockery::close();
        }

        parent::tearDown();
    }

    /**
     * `isSetup()` must complete without throwing when invoked against a
     * non-Eloquent identity — the cache-prefix builder's FQCN fallback path is
     * exercised on the way in. The behaviour proved here is "non-Eloquent
     * identities do not break the cached read"; the FQCN composition itself is
     * private to the manager.
     *
     * @return void
     */
    public function testIsSetupCompletesForNonEloquentIdentityWithoutThrowing(): void
    {
        $identity = new NonEloquentIdentity('plain-1', mfaEnabled: false);

        Auth::shouldReceive('user')->andReturn($identity);

        self::assertFalse($this->manager()->isSetup());
    }

    /**
     * `assertFactorOwnership()` must reject a non-Eloquent factor whose owner
     * FQCN matches but whose identifier is non-scalar — exercising the
     * `sameIdentifier()` short-circuit on the non-string-non-int branch.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testNonScalarIdentifierIsRejectedAsOwnershipMismatch(): void
    {
        $identity = new NonEloquentIdentity(['nested' => 'array'], mfaEnabled: false);

        Auth::shouldReceive('user')->andReturn($identity);

        $factor = new InMemoryFactor(driver: 'totp', authenticatable: $identity);

        $driver = \Mockery::mock(FactorDriver::class);
        $driver->shouldNotReceive('verify');

        $this->stubDriver('totp', $driver);

        // Both sides of the identifier comparison are non-scalar so
        // `sameIdentifier()` collapses to false and the manager throws.
        $this->expectException(FactorOwnershipMismatchException::class);

        $this->manager()->verify('totp', $factor, '000000');
    }

    /**
     * `issueBackupCodes()` must accept a non-Eloquent identity and persist the
     * new batch with the identity's FQCN as the morph type — exercising the
     * FQCN fallback inside the rotation flow.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Throwable
     */
    public function testIssueBackupCodesAcceptsNonEloquentIdentity(): void
    {
        $identity = new NonEloquentIdentity('plain-issue', mfaEnabled: false);

        Auth::shouldReceive('user')->andReturn($identity);

        $codes = $this->manager()->issueBackupCodes(2);

        self::assertCount(2, $codes);

        // Persisted rows must carry the identity's FQCN as the morph type —
        // proving the `: $identity::class` fallback fired.
        self::assertCount(
            2,
            Factor::query()
                ->where('authenticatable_type', NonEloquentIdentity::class)
                ->where('authenticatable_id', 'plain-issue')
                ->where('driver', 'backup_code')
                ->get(),
        );
    }

    /**
     * Without an authenticated identity, `challenge()` short-circuits before
     * any driver lookup — but with an identity present and an extension that
     * fails the `FactorDriver` contract, the manager surfaces a clear
     * `LogicException` rather than a fatal type error inside the dispatch path.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testChallengeThrowsLogicExceptionForNonFactorDriverExtension(): void
    {
        $identity = new NonEloquentIdentity('plain-id', mfaEnabled: false);

        Auth::shouldReceive('user')->andReturn($identity);

        $factor = new InMemoryFactor(driver: 'broken', authenticatable: $identity);

        $manager = $this->manager();
        $manager->extend('broken', fn (): \stdClass => new \stdClass);

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('Driver [broken] must implement');

        $manager->challenge('broken', $factor);
    }

    /**
     * Resolve the package's MFA manager from the container.
     *
     * @return \SineMacula\Laravel\Mfa\MfaManager
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function manager(): MfaManager
    {
        $manager = $this->container()->make('mfa');
        Assert::assertInstanceOf(MfaManager::class, $manager);

        return $manager;
    }

    /**
     * Register a stub driver under the given name on the MFA manager.
     *
     * @param  string  $name
     * @param  \SineMacula\Laravel\Mfa\Contracts\FactorDriver  $driver
     * @return void
     */
    private function stubDriver(string $name, FactorDriver $driver): void
    {
        $this->manager()->extend($name, fn (): FactorDriver => $driver);
    }
}
