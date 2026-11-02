<?php

declare(strict_types = 1);

namespace Tests\Unit;

use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Assert;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Contracts\FactorDriver;
use SineMacula\Laravel\Mfa\Events\MfaFactorDisabled;
use SineMacula\Laravel\Mfa\Exceptions\FactorOwnershipMismatchException;
use SineMacula\Laravel\Mfa\MfaManager;
use SineMacula\Laravel\Mfa\Models\Factor;
use Tests\Fixtures\Identities\TestUser;

/**
 * Cross-account factor enforcement at the manager boundary.
 *
 * Closes the MFA-bypass / factor-tampering primitive: every entry- point method
 * (`challenge`, `verify`, `disable`) rejects a factor that does not belong to
 * the current identity.
 *
 * Each test exercises the "natural endpoint shape" attack: the acting identity
 * is one user, the supplied factor belongs to a different user, and the manager
 * must throw before any mutation, driver dispatch, or event emission.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(MfaManager::class)]
final class MfaManagerOwnershipTest extends MfaManagerTestCase
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
     * `disable()` must throw on the same cross-account shape, and never delete
     * the underlying row.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testDisableRejectsEloquentFactorOwnedByDifferentIdentity(): void
    {
        [, $attacker, $victimsFactor] = $this->stageCrossAccount();

        $this->actingAs($attacker);

        Event::fake();

        $this->expectException(FactorOwnershipMismatchException::class);

        try {
            $this->manager()->disable($victimsFactor);
        } finally {
            self::assertNotNull(Factor::query()->find($victimsFactor->getKey()));
            Event::assertNotDispatched(MfaFactorDisabled::class);
        }
    }

    /**
     * Stage the cross-account attack shape used by the verify / challenge /
     * disable regression tests: build two MFA- enabled users and persist a
     * factor owned by the first.
     *
     * @return array{0: \Tests\Fixtures\Identities\TestUser, 1: \Tests\Fixtures\Identities\TestUser, 2: \SineMacula\Laravel\Mfa\Models\Factor}
     */
    private function stageCrossAccount(): array
    {
        $victim = TestUser::query()->create([
            'email'       => 'victim@example.test',
            'mfa_enabled' => true,
        ]);

        $attacker = TestUser::query()->create([
            'email'       => 'attacker@example.test',
            'mfa_enabled' => true,
        ]);

        /** @var \SineMacula\Laravel\Mfa\Models\Factor $victimsFactor */
        $victimsFactor = Factor::query()->create([
            'authenticatable_type' => $victim::class,
            'authenticatable_id'   => (string) $victim->id,
            'type'                 => 'totp',
            'secret'               => 'JBSWY3DPEHPK3PXP',
        ]);

        return [$victim, $attacker, $victimsFactor];
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
}
