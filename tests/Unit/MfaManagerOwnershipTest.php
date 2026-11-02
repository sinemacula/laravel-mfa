<?php

declare(strict_types = 1);

namespace Tests\Unit;

use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Assert;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Contracts\FactorDriver;
use SineMacula\Laravel\Mfa\Events\MfaFactorDisabled;
use SineMacula\Laravel\Mfa\Events\MfaFactorEnrolled;
use SineMacula\Laravel\Mfa\Exceptions\FactorOwnershipMismatchException;
use SineMacula\Laravel\Mfa\MfaManager;
use SineMacula\Laravel\Mfa\Models\Factor;
use Tests\Fixtures\Factors\InMemoryFactor;
use Tests\Fixtures\Identities\TestUser;

/**
 * Cross-account factor enforcement at the manager boundary.
 *
 * Closes the MFA-bypass / factor-tampering primitive: every entry- point method
 * (`challenge`, `verify`, `disable`) rejects a factor that does not belong to
 * the current identity, and `enroll()` stamps ownership rather than trusting
 * caller-supplied morph columns.
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
     * Test enroll() overwrites caller-supplied morph_id with current identity.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testEnrollOverwritesCallerSuppliedMorphId(): void
    {
        [$attacker, $factor] = $this->stageEnrollHijackAttempt();

        $this->manager()->enroll($factor);

        $factor->refresh();

        self::assertSame((string) $attacker->id, $factor->authenticatable_id);
    }

    /**
     * Test enroll() overwrites caller-supplied morph_type with current
     * identity.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testEnrollOverwritesCallerSuppliedMorphType(): void
    {
        [$attacker, $factor] = $this->stageEnrollHijackAttempt();

        $this->manager()->enroll($factor);

        $factor->refresh();

        self::assertSame($attacker::class, $factor->authenticatable_type);
    }

    /**
     * Test enroll() dispatches MfaFactorEnrolled even when caller spoofs morph
     * columns.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testEnrollDispatchesEnrolledEventWhenCallerSpoofsMorphColumns(): void
    {
        [, $factor] = $this->stageEnrollHijackAttempt();

        Event::fake([MfaFactorEnrolled::class]);

        $this->manager()->enroll($factor);

        Event::assertDispatched(MfaFactorEnrolled::class);
    }

    /**
     * `enroll()` must NOT silently rewrite the morph columns of an
     * already-persisted factor row — that would let an attacker hijack any
     * factor whose primary key they could enumerate by passing it straight from
     * request input. An existing row is treated like a verify/disable target:
     * ownership has to already match.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testEnrollRejectsExistingRowOwnedByDifferentIdentity(): void
    {
        [$victim, $attacker, $victimsFactor] = $this->stageCrossAccount();

        $this->actingAs($attacker);

        Event::fake([MfaFactorEnrolled::class]);

        $this->expectException(FactorOwnershipMismatchException::class);

        try {
            $this->manager()->enroll($victimsFactor);
        } finally {
            $victimsFactor->refresh();

            // The existing row must be untouched — morph columns still point at
            // the original victim. Both users share a class (TestUser), so the
            // diagnostic value is that the row's foreign key is the victim's
            // id, not the attacker's.
            self::assertSame((string) $victim->id, $victimsFactor->authenticatable_id);
            self::assertSame($victim::class, $victimsFactor->authenticatable_type);

            Event::assertNotDispatched(MfaFactorEnrolled::class);
        }
    }

    /**
     * `enroll()` of a non-Eloquent factor must reject the call when the
     * factor's reported owner does not match the current identity. Mirrors the
     * verify/challenge/disable enforcement so the four entry points present a
     * single boundary, not three.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testEnrollRejectsNonEloquentFactorOwnedByDifferentIdentity(): void
    {
        $user = TestUser::query()->create([
            'email'       => 'enroll-acting@example.test',
            'mfa_enabled' => true,
        ]);

        $foe = TestUser::query()->create([
            'email'       => 'enroll-foe@example.test',
            'mfa_enabled' => true,
        ]);

        $this->actingAs($user);

        Event::fake([MfaFactorEnrolled::class]);

        $factor = new InMemoryFactor(type: 'totp', authenticatable: $foe);

        $this->expectException(FactorOwnershipMismatchException::class);

        try {
            $this->manager()->enroll($factor);
        } finally {
            Event::assertNotDispatched(MfaFactorEnrolled::class);
        }
    }

    /**
     * The matching-identity branch of non-Eloquent `enroll()` must succeed
     * end-to-end: persistence is the consumer's job for non-Eloquent factors,
     * but the cache invalidation and lifecycle event MUST still fire.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testEnrollAcceptsNonEloquentFactorOwnedByCurrentIdentity(): void
    {
        $user = TestUser::query()->create([
            'email'       => 'enroll-ok@example.test',
            'mfa_enabled' => true,
        ]);

        $this->actingAs($user);

        Event::fake([MfaFactorEnrolled::class]);

        $factor = new InMemoryFactor(type: 'totp', authenticatable: $user);

        $this->manager()->enroll($factor);

        Event::assertDispatched(MfaFactorEnrolled::class);
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

    /**
     * Stage a cross-account enrol hijack attempt: the attacker is
     * authenticated, but the supplied factor's morph columns point at the
     * victim. Returns the attacker and the spoofed factor for the assertions to
     * observe.
     *
     * @return array{0: \Tests\Fixtures\Identities\TestUser, 1: \SineMacula\Laravel\Mfa\Models\Factor}
     */
    private function stageEnrollHijackAttempt(): array
    {
        $victim = TestUser::query()->create([
            'email'       => 'enroll-victim@example.test',
            'mfa_enabled' => true,
        ]);

        $attacker = TestUser::query()->create([
            'email'       => 'enroll-attacker@example.test',
            'mfa_enabled' => true,
        ]);

        $this->actingAs($attacker);

        $factor                       = new Factor;
        $factor->type                 = 'totp';
        $factor->secret               = 'JBSWY3DPEHPK3PXP';
        $factor->authenticatable_type = $victim::class;
        $factor->authenticatable_id   = (string) $victim->id;

        return [$attacker, $factor];
    }
}
