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
use Tests\Fixtures\SecondaryUser;
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
     * Test enrol overwrites caller-supplied morph_id with current identity.
     *
     * @return void
     */
    public function testEnrolOverwritesCallerSuppliedMorphId(): void
    {
        [$attacker, $factor] = $this->stageEnrolHijackAttempt();

        $this->manager()->enrol($factor);

        $factor->refresh();

        self::assertSame((string) $attacker->id, $factor->authenticatable_id);
    }

    /**
     * Test enrol overwrites caller-supplied morph_type with current identity.
     *
     * @return void
     */
    public function testEnrolOverwritesCallerSuppliedMorphType(): void
    {
        [$attacker, $factor] = $this->stageEnrolHijackAttempt();

        $this->manager()->enrol($factor);

        $factor->refresh();

        self::assertSame($attacker::class, $factor->authenticatable_type);
    }

    /**
     * Test enrol dispatches MfaFactorEnrolled even when caller spoofs morph columns.
     *
     * @return void
     */
    public function testEnrolDispatchesEnrolledEventWhenCallerSpoofsMorphColumns(): void
    {
        [, $factor] = $this->stageEnrolHijackAttempt();

        Event::fake([MfaFactorEnrolled::class]);

        $this->manager()->enrol($factor);

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
     * `enrol()` must NOT silently rewrite the morph columns of an
     * already-persisted factor row — that would let an attacker hijack
     * any factor whose primary key they could enumerate by passing it
     * straight from request input. An existing row is treated like a
     * verify/disable target: ownership has to already match.
     *
     * @return void
     */
    public function testEnrolRejectsExistingRowOwnedByDifferentIdentity(): void
    {
        [$victim, $attacker, $victimsFactor] = $this->stageCrossAccount();

        $this->actingAs($attacker);

        Event::fake([MfaFactorEnrolled::class]);

        $this->expectException(FactorOwnershipMismatchException::class);

        try {
            $this->manager()->enrol($victimsFactor);
        } finally {
            $victimsFactor->refresh();

            // The existing row must be untouched — morph columns still
            // point at the original victim. Both users share a class
            // (TestUser), so the diagnostic value is that the row's
            // foreign key is the victim's id, not the attacker's.
            self::assertSame((string) $victim->id, $victimsFactor->authenticatable_id);
            self::assertSame($victim::class, $victimsFactor->authenticatable_type);

            Event::assertNotDispatched(MfaFactorEnrolled::class);
        }
    }

    /**
     * `enrol()` of a non-Eloquent factor must reject the call when the
     * factor's reported owner does not match the current identity.
     * Mirrors the verify/challenge/disable enforcement so the four
     * entry points present a single boundary, not three.
     *
     * @return void
     */
    public function testEnrolRejectsNonEloquentFactorOwnedByDifferentIdentity(): void
    {
        $user = TestUser::query()->create([
            'email'       => 'enrol-acting@example.test',
            'mfa_enabled' => true,
        ]);

        $foe = TestUser::query()->create([
            'email'       => 'enrol-foe@example.test',
            'mfa_enabled' => true,
        ]);

        $this->actingAs($user);

        Event::fake([MfaFactorEnrolled::class]);

        $factor = new InMemoryFactor(driver: 'totp', authenticatable: $foe);

        $this->expectException(FactorOwnershipMismatchException::class);

        try {
            $this->manager()->enrol($factor);
        } finally {
            Event::assertNotDispatched(MfaFactorEnrolled::class);
        }
    }

    /**
     * The matching-identity branch of non-Eloquent `enrol()` must
     * succeed end-to-end: persistence is the consumer's job for
     * non-Eloquent factors, but the cache invalidation and lifecycle
     * event MUST still fire.
     *
     * @return void
     */
    public function testEnrolAcceptsNonEloquentFactorOwnedByCurrentIdentity(): void
    {
        $user = TestUser::query()->create([
            'email'       => 'enrol-ok@example.test',
            'mfa_enabled' => true,
        ]);

        $this->actingAs($user);

        Event::fake([MfaFactorEnrolled::class]);

        $factor = new InMemoryFactor(driver: 'totp', authenticatable: $user);

        $this->manager()->enrol($factor);

        Event::assertDispatched(MfaFactorEnrolled::class);
    }

    /**
     * The non-Eloquent assertion branch must also reject a factor
     * whose owner has the same identifier but a different class —
     * `User #1` and `Admin #1` are distinct identities even when
     * their primary keys collide.
     *
     * @return void
     */
    public function testVerifyRejectsNonEloquentFactorOwnedByDifferentClassWithSameIdentifier(): void
    {
        $primary = TestUser::query()->create(['email' => 'primary@example.test']);

        // Force the secondary identity onto the same primary-key value
        // so the only difference is the FQCN — proving the manager
        // distinguishes by class, not just ID.
        $secondary = SecondaryUser::query()->create(['email' => 'secondary@example.test']);
        $secondary->forceFill(['id' => $primary->getKey()])->saveQuietly();
        $secondary->refresh();

        $this->actingAs($primary);

        $factor = new InMemoryFactor(driver: 'totp', authenticatable: $secondary);

        $driver = \Mockery::mock(FactorDriver::class);
        $driver->shouldNotReceive('verify');

        $this->stubDriver('totp', $driver);

        $this->expectException(FactorOwnershipMismatchException::class);

        $this->manager()->verify('totp', $factor, self::WRONG_CODE);
    }

    /**
     * Stage a cross-account enrol hijack attempt: the attacker is
     * authenticated, but the supplied factor's morph columns point at
     * the victim. Returns the attacker and the spoofed factor for
     * the assertions to observe.
     *
     * @return array{0: \Tests\Fixtures\TestUser, 1: \SineMacula\Laravel\Mfa\Models\Factor}
     */
    private function stageEnrolHijackAttempt(): array
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

        $factor                       = new Factor;
        $factor->driver               = 'totp';
        $factor->secret               = 'JBSWY3DPEHPK3PXP';
        $factor->authenticatable_type = $victim::class;
        $factor->authenticatable_id   = (string) $victim->id;

        return [$attacker, $factor];
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
