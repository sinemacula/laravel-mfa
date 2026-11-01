<?php

declare(strict_types = 1);

namespace Tests\Unit\RecoveryCodes;

use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Enums\FactorStatus;
use SineMacula\Laravel\Mfa\Events\MfaFactorEnrolled;
use SineMacula\Laravel\Mfa\Factors\FactorService;
use SineMacula\Laravel\Mfa\MfaManager;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\RecoveryCodes\BackupCodeDriver;
use SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeService;
use Tests\Fixtures\Drivers\NoopFactorDriver;
use Tests\Fixtures\Exceptions\MidRotationFailureException;
use Tests\Fixtures\Identities\FactorHolder;
use Tests\Fixtures\Identities\SecondaryUser;
use Tests\Fixtures\Identities\TestUser;
use Tests\TestCase;

/**
 * Tests for `RecoveryCodeService`: a batch of backup codes replaces exactly the
 * current identity's previous batch, atomically, and is returned once.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RecoveryCodeService::class)]
final class RecoveryCodeServiceTest extends TestCase
{
    /**
     * A guest is issued nothing, and nothing is written.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testIssuesNothingToAGuest(): void
    {
        Event::fake([MfaFactorEnrolled::class]);

        self::assertSame([], $this->service()->issueBackupCodes($this->manager()));
        self::assertSame(0, Factor::query()->count());
        Event::assertNotDispatched(MfaFactorEnrolled::class);
    }

    /**
     * A backup-code driver that is not the shipped one is refused.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testRefusesADriverThatIsNotTheBackupCodeDriver(): void
    {
        $this->signIn('refused@example.com');

        $this->manager()->extend(BackupCodeDriver::NAME, fn (): NoopFactorDriver => new NoopFactorDriver);

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('Driver [backup_code] must be a ' . BackupCodeDriver::class . ' instance to issue backup codes.');

        $this->service()->issueBackupCodes($this->manager());
    }

    /**
     * Each code is stored as a backup-code factor of the identity holding its
     * hash, and enrolled with an event, and the plaintext codes are returned.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testStoresEachCodeHashedAndReturnsThePlaintext(): void
    {
        $user = $this->signIn('issue@example.com');

        Event::fake([MfaFactorEnrolled::class]);

        $codes = $this->service()->issueBackupCodes($this->manager(), 3);

        self::assertCount(3, $codes);

        $driver = $this->driver();
        $stored = $this->backupCodes($user)->map(static fn (Factor $factor): ?string => $factor->getSecret())->sort()->values()->all();
        $hashes = collect($codes)->map(static fn (string $code): string => $driver->hash($code))->sort()->values()->all();

        self::assertSame($hashes, $stored);
        Event::assertDispatchedTimes(MfaFactorEnrolled::class, 3);
        Event::assertDispatched(
            MfaFactorEnrolled::class,
            static fn (MfaFactorEnrolled $event): bool => $event->driver === BackupCodeDriver::NAME
                && $event->identity                                      === $user
                && $event->factor instanceof Factor
                && $event->factor->exists,
        );
    }

    /**
     * Without a count, the driver's configured count is issued.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testIssuesTheConfiguredCountByDefault(): void
    {
        $this->signIn('count@example.com');

        self::assertCount(10, $this->service()->issueBackupCodes($this->manager()));
    }

    /**
     * A new batch replaces the identity's previous batch, and leaves its other
     * factors and other identities' backup codes alone.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testReplacesOnlyTheIdentitysPreviousBatch(): void
    {
        $user     = $this->signIn('replace@example.com');
        $neighbor = TestUser::query()->create(['email' => 'neighbor@example.com']);

        $previous = $this->addFactor($user::class, $user->id, BackupCodeDriver::NAME);
        $totp     = $this->addFactor($user::class, $user->id, 'totp');
        $other    = $this->addFactor($neighbor::class, $neighbor->id, BackupCodeDriver::NAME);
        $foreign  = $this->addFactor(SecondaryUser::class, $user->id, BackupCodeDriver::NAME);

        $this->service()->issueBackupCodes($this->manager(), 2);

        self::assertFalse(Factor::query()->whereKey($previous->getKey())->exists());
        self::assertTrue(Factor::query()->whereKey($totp->getKey())->exists());
        self::assertTrue(Factor::query()->whereKey($other->getKey())->exists());
        self::assertTrue(Factor::query()->whereKey($foreign->getKey())->exists());
        self::assertCount(2, $this->backupCodes($user));
    }

    /**
     * A failure part-way through a rotation keeps the previous batch.
     *
     * @return void
     */
    public function testAFailedRotationKeepsThePreviousBatch(): void
    {
        $user     = $this->signIn('rollback@example.com');
        $previous = $this->addFactor($user::class, $user->id, BackupCodeDriver::NAME);
        $enrolled = 0;

        Event::listen(MfaFactorEnrolled::class, static function () use (&$enrolled): void {
            if (++$enrolled === 2) {
                throw new MidRotationFailureException('Failed mid-rotation.');
            }
        });

        try {
            $this->service()->issueBackupCodes($this->manager(), 3);
            self::fail('The rotation was expected to fail.');
        } catch (\Throwable $exception) {
            self::assertInstanceOf(MidRotationFailureException::class, $exception);
            self::assertCount(1, $this->backupCodes($user));
            self::assertTrue(Factor::query()->whereKey($previous->getKey())->exists());
        }
    }

    /**
     * The identity's factors include the issued codes at once.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testTheIssuedCodesAreSeenAtOnce(): void
    {
        $this->signIn('cache@example.com');

        $factors = $this->container()->make(FactorService::class);

        self::assertCount(0, $factors->getFactors() ?? collect([1]));

        $this->service()->issueBackupCodes($this->manager(), 2);

        self::assertCount(2, $factors->getFactors() ?? collect());
    }

    /**
     * Each issued code is stored confirmed, usable as soon as it is issued, so
     * an identity using the shipped trait that holds only backup codes is set
     * up.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testIssuedCodesAreConfirmedAndCountAsSetUp(): void
    {
        $holder = FactorHolder::query()->create(['email' => 'holder@example.com']);

        $this->actingAs($holder);

        $factors = $this->container()->make(FactorService::class);

        self::assertFalse($factors->isSetup());

        $this->service()->issueBackupCodes($this->manager(), 2);

        $statuses = Factor::query()
            ->where('authenticatable_id', (string) $holder->id)
            ->pluck('status')
            ->all();

        self::assertSame([FactorStatus::CONFIRMED->value, FactorStatus::CONFIRMED->value], $statuses);
        self::assertTrue($holder->isMfaEnabled());
        self::assertTrue($factors->isSetup());
    }

    /**
     * Resolve the package's MFA manager, the driver registry the service is
     * called with.
     *
     * @return \SineMacula\Laravel\Mfa\MfaManager
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function manager(): MfaManager
    {
        $manager = $this->container()->make('mfa');

        self::assertInstanceOf(MfaManager::class, $manager);

        return $manager;
    }

    /**
     * Resolve the backup-code service.
     *
     * @return \SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeService
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function service(): RecoveryCodeService
    {
        return $this->container()->make(RecoveryCodeService::class);
    }

    /**
     * Resolve the backup-code driver.
     *
     * @return \SineMacula\Laravel\Mfa\RecoveryCodes\BackupCodeDriver
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function driver(): BackupCodeDriver
    {
        $driver = $this->manager()->driver(BackupCodeDriver::NAME);

        self::assertInstanceOf(BackupCodeDriver::class, $driver);

        return $driver;
    }

    /**
     * Create a test user and authenticate as them.
     *
     * @param  string  $email
     * @return \Tests\Fixtures\Identities\TestUser
     */
    private function signIn(string $email): TestUser
    {
        /** @var \Tests\Fixtures\Identities\TestUser $user */
        $user = TestUser::query()->create(['email' => $email]);

        $this->actingAs($user);

        return $user;
    }

    /**
     * Add a factor owned by the given type and identifier.
     *
     * @param  string  $type
     * @param  int  $id
     * @param  string  $driver
     * @return \SineMacula\Laravel\Mfa\Models\Factor
     */
    private function addFactor(string $type, int $id, string $driver): Factor
    {
        /** @var \SineMacula\Laravel\Mfa\Models\Factor */
        return Factor::query()->create([
            'authenticatable_type' => $type,
            'authenticatable_id'   => (string) $id,
            'type'                 => $driver,
            'secret'               => 'secret-' . $driver,
        ]);
    }

    /**
     * The user's stored backup-code factors.
     *
     * @param  \Tests\Fixtures\Identities\TestUser  $user
     * @return \Illuminate\Support\Collection<int, \SineMacula\Laravel\Mfa\Models\Factor>
     */
    private function backupCodes(TestUser $user): Collection
    {
        /** @var \Illuminate\Support\Collection<int, \SineMacula\Laravel\Mfa\Models\Factor> */
        return Factor::query()
            ->where('authenticatable_type', $user::class)
            ->where('authenticatable_id', (string) $user->id)
            ->where('type', BackupCodeDriver::NAME)
            ->get()
            ->toBase();
    }
}
