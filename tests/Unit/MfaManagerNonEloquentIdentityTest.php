<?php

declare(strict_types = 1);

namespace Tests\Unit;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Support\Facades\Auth;
use PHPUnit\Framework\Assert;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Contracts\FactorDriver;
use SineMacula\Laravel\Mfa\Exceptions\FactorOwnershipMismatchException;
use SineMacula\Laravel\Mfa\MfaManager;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Models\RecoveryCode;
use Tests\Fixtures\Factors\InMemoryFactor;
use Tests\Fixtures\Identities\NonEloquentIdentity;

/**
 * Coverage for the FQCN-fallback paths behind the manager.
 *
 * `Support\CurrentIdentity::typeOf()`, which
 * `Factors\FactorOwnership::assert()`, the proof store and recovery code
 * generation all use, branches on whether the identity is a `Model` —
 * Eloquent identities use `getMorphClass()`, non-Eloquent identities fall back
 * to a strict FQCN comparison. The shipped test identities (`TestUser`,
 * `SecondaryUser`, `NonScalarIdentifierUser`) are all Eloquent, so a dedicated
 * non-Eloquent fixture is needed to drive the FQCN branches and keep coverage
 * at 100%.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(MfaManager::class)]
final class MfaManagerNonEloquentIdentityTest extends MfaManagerTestCase
{
    /**
     * Tear down Mockery expectations between test cases.
     *
     * @return void
     */
    #[\Override]
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
     * `FactorOwnership::assert()` must reject a non-Eloquent factor whose owner
     * FQCN matches but whose identifier is non-scalar — exercising the
     * `isSameIdentifier()` short-circuit on the non-string-non-int branch.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testNonScalarIdentifierIsRejectedAsOwnershipMismatch(): void
    {
        $identity = new NonEloquentIdentity(['nested' => 'array'], mfaEnabled: false);

        Auth::shouldReceive('user')->andReturn($identity);

        $factor = new InMemoryFactor(type: 'totp', authenticatable: $identity);

        $driver = \Mockery::mock(FactorDriver::class);
        $driver->shouldNotReceive('verify');

        $this->stubDriver('totp', $driver);

        // Both sides of the identifier comparison are non-scalar so
        // `isSameIdentifier()` collapses to false and the manager throws.
        $this->expectException(FactorOwnershipMismatchException::class);

        $this->manager()->verify('totp', $factor, '000000');
    }

    /**
     * `generateRecoveryCodes()` must accept a non-Eloquent identity and store
     * the new set with the identity's FQCN as the owner type, exercising the
     * FQCN fallback inside the replacement.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Throwable
     */
    public function testGenerateRecoveryCodesAcceptsNonEloquentIdentity(): void
    {
        $identity = new NonEloquentIdentity('plain-issue', mfaEnabled: true);
        $config   = $this->container()->make(Repository::class);

        $config->set('hashing.bcrypt.rounds', 4);
        $config->set('mfa.recovery_codes.count', 2);
        $config->set('mfa.applications.web', ['recovery_codes' => ['enabled' => true], 'first_factor' => ['method' => 'password', 'channel' => 'password']]);

        Factor::query()->create([
            'authenticatable_type' => NonEloquentIdentity::class,
            'authenticatable_id'   => 'plain-issue',
            'type'                 => 'totp',
            'status'               => 'confirmed',
        ]);

        $this->actingAs($identity);

        self::assertCount(2, $this->manager()->generateRecoveryCodes());

        // Stored rows must carry the identity's FQCN as the owner type,
        // proving the `: $identity::class` fallback fired.
        self::assertSame(
            2,
            RecoveryCode::query()
                ->where('authenticatable_type', NonEloquentIdentity::class)
                ->where('authenticatable_id', 'plain-issue')
                ->count(),
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

        $factor = new InMemoryFactor(type: 'broken', authenticatable: $identity);

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
