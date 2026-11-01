<?php

declare(strict_types = 1);

namespace Tests\Unit\Enrollment;

use Illuminate\Database\Eloquent\Relations\Relation;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Enrollment\EnrollmentService;
use SineMacula\Laravel\Mfa\Events\MfaFactorEnrolled;
use SineMacula\Laravel\Mfa\Exceptions\FactorOwnershipMismatchException;
use SineMacula\Laravel\Mfa\Factors\FactorService;
use SineMacula\Laravel\Mfa\Models\Factor;
use Tests\Fixtures\InMemoryFactor;
use Tests\Fixtures\NonModelEloquentBackupCodeFactor;
use Tests\Fixtures\SecondaryUser;
use Tests\Fixtures\TestUser;
use Tests\TestCase;

/**
 * Tests for `EnrollmentService`: a new factor is stamped as the current
 * identity's and saved, an existing one only when it is already theirs, and
 * every enrolment clears the identity's cached factors and is reported.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(EnrollmentService::class)]
final class EnrollmentServiceTest extends TestCase
{
    /**
     * Forget any morph map a test set.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Relation::morphMap([], false);

        parent::tearDown();
    }

    /**
     * A guest enrols nothing and nothing is reported.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAGuestEnrollsNothing(): void
    {
        Event::fake([MfaFactorEnrolled::class]);

        $this->service()->enroll($this->newFactor());

        self::assertSame(0, Factor::query()->count());
        Event::assertNotDispatched(MfaFactorEnrolled::class);
    }

    /**
     * A new factor is stamped as the current identity's, overwriting any owner
     * the caller set, saved and reported.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testANewFactorIsStampedAsTheIdentitysAndSaved(): void
    {
        $user   = $this->signIn();
        $factor = $this->newFactor();

        $factor->setAttribute('authenticatable_type', SecondaryUser::class);
        $factor->setAttribute('authenticatable_id', '999');

        Event::fake([MfaFactorEnrolled::class]);

        $this->service()->enroll($factor);

        self::assertTrue($factor->exists);
        self::assertSame($user::class, $factor->getAttribute('authenticatable_type'));
        self::assertSame((string) $user->id, $factor->authenticatable_id);
        Event::assertDispatched(
            MfaFactorEnrolled::class,
            static fn (MfaFactorEnrolled $event): bool => $event->identity === $user
                && $event->factor                                          === $factor
                && $event->driver                                          === 'totp',
        );
    }

    /**
     * A new factor is stamped with the identity's morph alias.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testANewFactorIsStampedWithTheMorphAlias(): void
    {
        Relation::morphMap(['test-user' => TestUser::class]);

        $this->signIn();

        $factor = $this->newFactor();

        $this->service()->enroll($factor);

        self::assertSame('test-user', $factor->getAttribute('authenticatable_type'));
    }

    /**
     * An existing factor of the identity is saved again and reported.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAnExistingFactorOfTheIdentityIsSaved(): void
    {
        $user   = $this->signIn();
        $factor = $this->existingFactor($user::class, $user->id);

        $factor->setAttribute('label', 'Phone');

        Event::fake([MfaFactorEnrolled::class]);

        $this->service()->enroll($factor);

        self::assertSame('Phone', $factor->fresh()?->getAttribute('label'));
        Event::assertDispatched(MfaFactorEnrolled::class);
    }

    /**
     * An existing factor of another identity is refused, never re-owned.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAnExistingFactorOfAnotherIdentityIsRefused(): void
    {
        $this->signIn();

        $other  = TestUser::query()->create(['email' => 'other@example.com']);
        $factor = $this->existingFactor($other::class, $other->id);

        $factor->setAttribute('label', 'Hijacked');

        Event::fake([MfaFactorEnrolled::class]);

        try {
            $this->service()->enroll($factor);
            self::fail('Enrolling another identity\'s factor was expected to be refused.');
        } catch (FactorOwnershipMismatchException) {
            $stored = $factor->fresh();

            self::assertNotNull($stored);
            self::assertNull($stored->getAttribute('label'));
            self::assertSame((string) $other->id, $stored->authenticatable_id);
            Event::assertNotDispatched(MfaFactorEnrolled::class);
        }
    }

    /**
     * A non-Eloquent factor reporting the identity as its owner is enrolled.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testANonEloquentFactorOfTheIdentityIsEnrolled(): void
    {
        $user = $this->signIn();

        Event::fake([MfaFactorEnrolled::class]);

        $this->service()->enroll(new InMemoryFactor(driver: 'email', authenticatable: $user));

        Event::assertDispatched(MfaFactorEnrolled::class, static fn (MfaFactorEnrolled $event): bool => $event->driver === 'email');
    }

    /**
     * A non-Eloquent factor reporting another owner, or none, is refused.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testANonEloquentFactorOfAnotherOwnerIsRefused(): void
    {
        $this->signIn();

        $this->expectException(FactorOwnershipMismatchException::class);

        $this->service()->enroll(new NonModelEloquentBackupCodeFactor('hash'));
    }

    /**
     * Enrolling clears the identity's cached factors.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testEnrollingClearsTheIdentitysCachedFactors(): void
    {
        $this->signIn();

        $factors = $this->container()->make(FactorService::class);

        self::assertFalse($factors->isSetup());

        $this->service()->enroll($this->newFactor());

        self::assertTrue($factors->isSetup());
    }

    /**
     * Resolve the enrolment service.
     *
     * @return \SineMacula\Laravel\Mfa\Enrollment\EnrollmentService
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function service(): EnrollmentService
    {
        return $this->container()->make(EnrollmentService::class);
    }

    /**
     * Create a test user and authenticate as them.
     *
     * @return \Tests\Fixtures\TestUser
     */
    private function signIn(): TestUser
    {
        /** @var \Tests\Fixtures\TestUser $user */
        $user = TestUser::query()->create(['email' => 'enroll@example.com']);

        $this->actingAs($user);

        return $user;
    }

    /**
     * Build an unsaved TOTP factor.
     *
     * @return \SineMacula\Laravel\Mfa\Models\Factor
     */
    private function newFactor(): Factor
    {
        $factor = new Factor;

        $factor->setAttribute('driver', 'totp');
        $factor->setAttribute('secret', 'JBSWY3DPEHPK3PXP');

        return $factor;
    }

    /**
     * Create a TOTP factor owned by the given type and identifier.
     *
     * @param  string  $type
     * @param  int  $id
     * @return \SineMacula\Laravel\Mfa\Models\Factor
     */
    private function existingFactor(string $type, int $id): Factor
    {
        /** @var \SineMacula\Laravel\Mfa\Models\Factor */
        return Factor::query()->create([
            'authenticatable_type' => $type,
            'authenticatable_id'   => (string) $id,
            'driver'               => 'totp',
            'secret'               => 'JBSWY3DPEHPK3PXP',
        ]);
    }
}
