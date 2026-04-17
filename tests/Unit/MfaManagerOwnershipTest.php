<?php

declare(strict_types = 1);

namespace Tests\Unit;

use Illuminate\Support\Facades\Event;
use SineMacula\Laravel\Mfa\Contracts\FactorDriver;
use SineMacula\Laravel\Mfa\Events\MfaChallengeIssued;
use SineMacula\Laravel\Mfa\Events\MfaFactorDisabled;
use SineMacula\Laravel\Mfa\Events\MfaFactorEnrolled;
use SineMacula\Laravel\Mfa\Events\MfaVerified;
use SineMacula\Laravel\Mfa\Exceptions\FactorOwnershipMismatchException;
use SineMacula\Laravel\Mfa\MfaManager;
use SineMacula\Laravel\Mfa\Models\Factor;
use Tests\Fixtures\InMemoryFactor;
use Tests\Fixtures\TestUser;

/**
 * Cross-account factor enforcement at the manager boundary.
 *
 * Closes the MFA-bypass / factor-tampering primitive: every entry-
 * point method (`challenge`, `verify`, `disable`) rejects a factor
 * that does not belong to the current identity, and `enrol()` stamps
 * ownership rather than trusting caller-supplied morph columns.
 *
 * Each test exercises the "natural endpoint shape" attack: the
 * acting identity is one user, the supplied factor belongs to a
 * different user, and the manager must throw before any mutation,
 * driver dispatch, or event emission.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 *
 * @internal
 */
final class MfaManagerOwnershipTest extends MfaManagerTestCase
{
    /** @var string Right-shape OTP value used to drive the rejected verify() paths. */
    private const string WRONG_CODE = '000000';

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
     * `verify()` must throw when the supplied Eloquent factor's morph
     * columns do not point at the currently authenticated identity.
     *
     * @return void
     */
    public function testVerifyRejectsEloquentFactorOwnedByDifferentIdentity(): void
    {
        [$victim, $attacker, $victimsFactor] = $this->stageCrossAccount();

        $this->actingAs($attacker);

        $driver = \Mockery::mock(FactorDriver::class);
        $driver->shouldNotReceive('verify');

        $this->stubDriver('totp', $driver);

        Event::fake();

        $this->expectException(FactorOwnershipMismatchException::class);

        try {
            $this->manager()->verify('totp', $victimsFactor, self::WRONG_CODE);
        } finally {
            Event::assertNotDispatched(MfaVerified::class);
            self::assertNotNull($victim);
        }
    }

    /**
     * `challenge()` must throw on the same cross-account shape, and
     * never invoke the driver's `issueChallenge()`.
     *
     * @return void
     */
    public function testChallengeRejectsEloquentFactorOwnedByDifferentIdentity(): void
    {
        [, $attacker, $victimsFactor] = $this->stageCrossAccount();

        $this->actingAs($attacker);

        $driver = \Mockery::mock(FactorDriver::class);
        $driver->shouldNotReceive('issueChallenge');

        $this->stubDriver('totp', $driver);

        Event::fake();

        $this->expectException(FactorOwnershipMismatchException::class);

        try {
            $this->manager()->challenge('totp', $victimsFactor);
        } finally {
            Event::assertNotDispatched(MfaChallengeIssued::class);
        }
    }

    /**
     * `disable()` must throw on the same cross-account shape, and
     * never delete the underlying row.
     *
     * @return void
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
     * `enrol()` must overwrite caller-supplied morph columns with the
     * current identity — a consumer cannot enrol a factor against the
     * victim's account by pre-populating relation columns.
     *
     * @return void
     */
    public function testEnrolStampsCurrentIdentityOverCallerSuppliedMorphColumns(): void
    {
        $victim = TestUser::query()->create([
            'email'       => 'enrol-victim@example.test',
            'mfa_enabled' => true,
        ]);

        $attacker = TestUser::query()->create([
            'email'       => 'enrol-attacker@example.test',
            'mfa_enabled' => true,
        ]);

        $this->actingAs($attacker);

        $factor         = new Factor;
        $factor->driver = 'totp';
        $factor->secret = 'JBSWY3DPEHPK3PXP';
        // Caller pre-populates the morph columns to point at the victim;
        // the manager must overwrite them with the current identity.
        $factor->authenticatable_type = $victim::class;
        $factor->authenticatable_id   = (string) $victim->id;

        Event::fake([MfaFactorEnrolled::class]);

        $this->manager()->enrol($factor);

        $factor->refresh();

        self::assertSame((string) $attacker->id, $factor->authenticatable_id);
        self::assertSame($attacker::class, $factor->authenticatable_type);

        Event::assertDispatched(MfaFactorEnrolled::class);
    }

    /**
     * A non-Eloquent `Factor` whose `getAuthenticatable()` returns
     * `null` must be rejected — without an owner reference there is no
     * way to verify the factor was issued for the current identity.
     *
     * @return void
     */
    public function testVerifyRejectsNonEloquentFactorWithUnknownOwner(): void
    {
        $user = TestUser::query()->create(['email' => 'no-owner@example.test']);

        $this->actingAs($user);

        $factor = new InMemoryFactor(driver: 'totp');

        $driver = \Mockery::mock(FactorDriver::class);
        $driver->shouldNotReceive('verify');

        $this->stubDriver('totp', $driver);

        $this->expectException(FactorOwnershipMismatchException::class);

        $this->manager()->verify('totp', $factor, self::WRONG_CODE);
    }

    /**
     * A non-Eloquent `Factor` bound to a different identity must be
     * rejected even when the FQCN matches but the identifier does not.
     *
     * @return void
     */
    public function testVerifyRejectsNonEloquentFactorOwnedByDifferentIdentifier(): void
    {
        $user = TestUser::query()->create(['email' => 'right-class@example.test']);
        $foe  = TestUser::query()->create(['email' => 'wrong-id@example.test']);

        $this->actingAs($user);

        $factor = new InMemoryFactor(driver: 'totp', authenticatable: $foe);

        $driver = \Mockery::mock(FactorDriver::class);
        $driver->shouldNotReceive('verify');

        $this->stubDriver('totp', $driver);

        $this->expectException(FactorOwnershipMismatchException::class);

        $this->manager()->verify('totp', $factor, self::WRONG_CODE);
    }

    /**
     * Stage the cross-account attack shape used by the
     * verify / challenge / disable regression tests: build two MFA-
     * enabled users and persist a factor owned by the first.
     *
     * @return array{0: \Tests\Fixtures\TestUser, 1: \Tests\Fixtures\TestUser, 2: \SineMacula\Laravel\Mfa\Models\Factor}
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
            'driver'               => 'totp',
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
     */
    private function manager(): MfaManager
    {
        $manager = $this->container()->make('mfa');
        \PHPUnit\Framework\Assert::assertInstanceOf(MfaManager::class, $manager);

        return $manager;
    }
}
