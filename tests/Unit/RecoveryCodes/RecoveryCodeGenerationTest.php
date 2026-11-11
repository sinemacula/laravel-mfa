<?php

declare(strict_types = 1);

namespace Tests\Unit\RecoveryCodes;

use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Hash;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Events\Actor;
use SineMacula\Laravel\Mfa\Events\RecoveryCodesGenerated;
use SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException;
use SineMacula\Laravel\Mfa\Exceptions\SecretNotRevealedException;
use SineMacula\Laravel\Mfa\Exceptions\WriteCanceledException;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Models\IdentityState;
use SineMacula\Laravel\Mfa\Models\RecoveryCode;
use SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeService;
use SineMacula\Laravel\Mfa\Secrets\SecretResponse;
use Tests\Fixtures\Context\Callers;
use Tests\Fixtures\Exceptions\MidRotationFailureException;
use Tests\Fixtures\Identities\FactorHolder;
use Tests\Fixtures\Identities\NonEloquentIdentity;
use Tests\TestCase;
use Tests\Unit\Concerns\InteractsWithRecoveryCodes;

/**
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RecoveryCodeService::class)]
final class RecoveryCodeGenerationTest extends TestCase
{
    use InteractsWithRecoveryCodes;

    /**
     * Unformatted, from the configured alphabet; a secret refuses to be encoded
     * on its own, and the response helper reveals each one.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testReturnsTheSetOnceAsSecrets(): void
    {
        $holder = $this->signInHolder();
        $codes  = $this->recoveryCodes()->generate($holder, 'web');

        self::assertCount(10, $codes);

        foreach (self::plaintexts($codes) as $code) {
            self::assertMatchesRegularExpression('/^[23456789ABCDEFGHJKLMNPQRSTUVWXYZ]{13}$/', $code);
        }

        self::assertCount(10, array_unique(self::plaintexts($codes)));

        $body = SecretResponse::json(['recovery_codes' => $codes])->getContent();

        self::assertIsString($body);
        self::assertSame(['recovery_codes' => self::plaintexts($codes)], json_decode($body, true));

        $this->expectException(SecretNotRevealedException::class);

        json_encode($codes[0], JSON_THROW_ON_ERROR);
    }

    /**
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheConfiguredSettingsGovernTheSet(): void
    {
        config()->set('mfa.recovery_codes', ['count' => 3, 'length' => 16, 'alphabet' => 'abcdefghjk']);

        $codes = self::plaintexts($this->recoveryCodes()->generate($this->signInHolder(), 'web'));

        self::assertCount(3, $codes);

        foreach ($codes as $code) {
            self::assertMatchesRegularExpression('/^[ABCDEFGHJK]{16}$/', $code);
        }
    }

    /**
     * Never in plaintext, under the first generation; the state row records the
     * generation and its time.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testStoresEachCodeAsASaltedHash(): void
    {
        $this->travelTo(CarbonImmutable::parse('2026-11-01 09:30:00'));

        $holder = $this->signInHolder();
        $codes  = self::plaintexts($this->recoveryCodes()->generate($holder, 'web'));
        $stored = $this->storedCodes($holder);

        self::assertCount(10, $stored);

        foreach ($stored as $index => $row) {
            $hash = (string) $row->getCodeHash();

            self::assertNotContains($hash, $codes);
            self::assertSame('bcrypt', password_get_info($hash)['algoName']);
            self::assertSame(1, $row->getAttribute($row->getGenerationName()));
            self::assertTrue($row->isUsable());
            self::assertCount(1, array_filter($codes, static fn (string $code): bool => Hash::check($code, $hash)), 'Row ' . $index . ' matches no code.');
        }

        $state = $this->stateOf($holder);

        self::assertSame(1, $state->recovery_codes_generation);
        self::assertSame('2026-11-01 09:30:00', $state->recovery_codes_generated_at?->format('Y-m-d H:i:s'));
    }

    /**
     * As the application's passwords are.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testHashesWithTheConfiguredDriver(): void
    {
        if (!defined('PASSWORD_ARGON2ID')) {
            self::markTestSkipped('PHP was built without Argon2.');
        }

        config()->set('hashing.driver', 'argon2id');
        config()->set('hashing.argon', ['memory' => 1024, 'threads' => 1, 'time' => 1]);

        $this->container()->forgetInstance('hash');
        $this->container()->forgetInstance('hash.driver');

        $holder = $this->signInHolder();

        $this->recoveryCodes()->generate($holder, 'web');

        foreach ($this->storedCodes($holder) as $row) {
            self::assertSame('argon2id', password_get_info((string) $row->getCodeHash())['algoName']);
        }
    }

    /**
     * Every earlier code, used or not, is marked replaced at the new set's
     * time, the generation advances, and only the new codes redeem.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testANewSetReplacesTheOldOne(): void
    {
        $holder   = $this->signInHolder();
        $previous = self::plaintexts($this->recoveryCodes()->generate($holder, 'web'));

        self::assertTrue($this->recoveryCodes()->redeem($holder, $previous[0], self::redemptionBinding($holder, Purpose::STEP_UP))->passed);

        $this->travelTo(CarbonImmutable::parse('2026-11-02 10:00:00'));

        $current = self::plaintexts($this->recoveryCodes()->generate($holder, 'web'));

        $stored = $this->storedCodes($holder);

        self::assertCount(20, $stored);
        $replacedAt = static fn (RecoveryCode $row): ?string => $row->getReplacedAt()?->format('Y-m-d H:i:s');
        $generation = static fn (RecoveryCode $row): mixed => $row->getAttribute($row->getGenerationName());

        self::assertCount(10, $stored->filter(static fn (RecoveryCode $row): bool => $generation($row) === 1 && $replacedAt($row) === '2026-11-02 10:00:00'));
        self::assertCount(10, $stored->filter(static fn (RecoveryCode $row): bool => $generation($row) === 2 && $row->isUsable()));
        self::assertSame(2, $this->stateOf($holder)->recovery_codes_generation);

        self::assertFalse($this->recoveryCodes()->redeem($holder, $previous[1], self::redemptionBinding($holder, Purpose::STEP_UP))->passed);
        self::assertTrue($this->recoveryCodes()->redeem($holder, $current[1], self::redemptionBinding($holder, Purpose::STEP_UP))->passed);
    }

    /**
     * @return void
     *
     * @throws \Throwable
     */
    public function testOnlyTheIdentitysOwnSetIsReplaced(): void
    {
        $neighbor = FactorHolder::query()->create(['email' => 'neighbor@example.com']);

        $this->addFactor($neighbor);
        $this->recoveryCodes()->generate($neighbor, 'web');

        $this->recoveryCodes()->generate($this->signInHolder(), 'web');

        self::assertCount(10, $this->storedCodes($neighbor)->filter(static fn (RecoveryCode $row): bool => $row->isUsable()));
    }

    /**
     * `RecoveryCodesGenerated` is dispatched once, after the commit, with the
     * size, generation and actor.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testReportsTheSetWithoutACode(): void
    {
        $holder = $this->signInHolder();
        $actor  = new Actor('admin', '7');

        Event::fake([RecoveryCodesGenerated::class]);

        $codes = self::plaintexts($this->recoveryCodes()->generate($holder, 'web', $actor));

        Event::assertDispatchedTimes(RecoveryCodesGenerated::class, 1);
        Event::assertDispatched(RecoveryCodesGenerated::class, static function (RecoveryCodesGenerated $event) use ($codes, $actor): bool {

            $payload = (string) json_encode([$event->context, $event->count, $event->generation]);

            foreach ($codes as $code) {
                if (str_contains($payload, $code)) {
                    return false;
                }
            }

            return $event->count === 10 && $event->generation === 1 && $event->actor === $actor && $event->context['application'] === 'web';
        });
    }

    /**
     * The whole replacement rolls back: the previous set still redeems, the
     * generation is unchanged and nothing is reported.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFailedReplacementKeepsThePreviousSet(): void
    {
        $holder   = $this->signInHolder();
        $previous = self::plaintexts($this->recoveryCodes()->generate($holder, 'web'));
        $inserted = 0;

        RecoveryCode::creating(static function () use (&$inserted): void {
            if (++$inserted === 4) {
                throw new MidRotationFailureException('Failed mid-replacement.');
            }
        });

        Event::fake([RecoveryCodesGenerated::class]);

        try {
            $this->recoveryCodes()->generate($holder, 'web');
            self::fail('The replacement was expected to fail.');
        } catch (MidRotationFailureException $exception) {
            self::assertSame('Failed mid-replacement.', $exception->getMessage());
        }

        Event::assertNotDispatched(RecoveryCodesGenerated::class);

        self::assertCount(10, $this->storedCodes($holder));
        self::assertSame(1, $this->stateOf($holder)->recovery_codes_generation);
        self::assertTrue($this->recoveryCodes()->redeem($holder, $previous[3], self::redemptionBinding($holder, Purpose::SIGN_IN))->passed);
    }

    /**
     * A code insert cancelled by a model event throws rather than committing a
     * partial set.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACanceledCodeSaveKeepsThePreviousSet(): void
    {
        $holder   = $this->signInHolder();
        $previous = self::plaintexts($this->recoveryCodes()->generate($holder, 'web'));
        $inserted = 0;

        RecoveryCode::creating(static function () use (&$inserted): bool {
            return ++$inserted !== 4;
        });

        $this->assertReplacementCanceled($holder, $previous, RecoveryCode::class);
    }

    /**
     * Throws rather than committing a set its state row does not record.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACanceledStateSaveKeepsThePreviousSet(): void
    {
        $holder   = $this->signInHolder();
        $previous = self::plaintexts($this->recoveryCodes()->generate($holder, 'web'));

        IdentityState::saving(static fn (): bool => false);

        $this->assertReplacementCanceled($holder, $previous, IdentityState::class);
    }

    /**
     * New codes are stored under the next generation before it is recorded, so
     * a redemption under the same lock sees one set, never both.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheOldSetIsReplacedBeforeTheNewOneIsStored(): void
    {
        $holder = $this->signInHolder();

        $this->recoveryCodes()->generate($holder, 'web');

        $usable = [];

        RecoveryCode::creating(function () use ($holder, &$usable): void {
            $usable[] = $this->storedCodes($holder)->filter(static fn (RecoveryCode $row): bool => $row->isUsable())->count();
        });

        $this->recoveryCodes()->generate($holder, 'web');

        self::assertSame(range(0, 9), $usable);
    }

    /**
     * Nothing is written.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRefusedWhenTheApplicationDoesNotAcceptRecoveryCodes(): void
    {
        config()->set('mfa.applications.web.recovery_codes.enabled', false);

        $holder = $this->signInHolder();

        $this->assertRefused(FailureReason::TYPE_NOT_ENABLED, fn () => $this->recoveryCodes()->generate($holder, 'web'));

        self::assertCount(0, $this->storedCodes($holder));
    }

    /**
     * An identity whose only factor is pending, and one with none.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRefusedWithoutAConfirmedFactor(): void
    {
        $pending = $this->signInHolder('pending@example.com', 'pending');
        $none    = $this->signInHolder('none@example.com', null);

        $this->assertRefused(FailureReason::NO_FACTOR, fn () => $this->recoveryCodes()->generate($pending, 'web'));
        $this->assertRefused(FailureReason::NO_FACTOR, fn () => $this->recoveryCodes()->generate($none, 'web'));

        self::assertCount(0, $this->storedCodes($pending));
    }

    /**
     * An identity whose own answer counts a pending factor is still refused,
     * and nothing is written.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheConfirmedFactorIsCheckedAgainUnderTheLock(): void
    {
        $identity = new NonEloquentIdentity('pending-only', mfaEnabled: true);

        Factor::query()->create([
            'authenticatable_type' => NonEloquentIdentity::class,
            'authenticatable_id'   => 'pending-only',
            'type'                 => 'totp',
            'status'               => 'pending',
        ]);

        $this->assertRefused(FailureReason::NO_FACTOR, fn () => $this->recoveryCodes()->generate($identity, 'web'));

        self::assertSame(0, RecoveryCode::query()->where('authenticatable_id', 'pending-only')->count());
    }

    /**
     * @return void
     */
    public function testRefusedForAMachineOrInactiveIdentity(): void
    {
        $machine  = new NonEloquentIdentity('machine', mfaEnabled: true, person: false);
        $inactive = new NonEloquentIdentity('inactive', mfaEnabled: true, active: false);

        $this->assertRefused(FailureReason::MACHINE_IDENTITY, fn () => $this->recoveryCodes()->generate($machine, 'web'));
        $this->assertRefused(FailureReason::IDENTITY_INACTIVE, fn () => $this->recoveryCodes()->generate($inactive, 'web'));
    }

    /**
     * An identity holding a set but no confirmed factor is not set up.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRecoveryCodesDoNotCountAsAFactor(): void
    {
        $holder = $this->signInHolder();
        $factor = $holder->authFactors()->firstOrFail();

        $this->recoveryCodes()->generate($holder, 'web');

        $factor->delete();

        self::assertCount(10, $this->storedCodes($holder));
        self::assertFalse($holder->isMfaEnabled());
        self::assertSame([], Mfa::factors(Callers::current()));
    }

    /**
     * The previous set stays stored, usable and redeemable, the generation
     * unchanged and nothing reported.
     *
     * @param  \Tests\Fixtures\Identities\FactorHolder  $holder
     * @param  list<string>  $previous
     * @param  class-string  $model
     * @return void
     *
     * @throws \Throwable
     */
    private function assertReplacementCanceled(FactorHolder $holder, array $previous, string $model): void
    {
        Event::fake([RecoveryCodesGenerated::class]);

        $thrown = null;

        try {
            $this->recoveryCodes()->generate($holder, 'web');
        } catch (WriteCanceledException $exception) {
            $thrown = $exception;
        }

        self::assertInstanceOf(WriteCanceledException::class, $thrown);
        self::assertStringContainsString($model, $thrown->getMessage());

        Event::assertNotDispatched(RecoveryCodesGenerated::class);

        self::assertCount(10, $this->storedCodes($holder));
        self::assertTrue($this->storedCodes($holder)->every(static fn (RecoveryCode $row): bool => $row->isUsable()));
        self::assertSame(1, $this->stateOf($holder)->recovery_codes_generation);

        IdentityState::flushEventListeners();
        RecoveryCode::flushEventListeners();

        self::assertTrue($this->recoveryCodes()->redeem($holder, $previous[3], self::redemptionBinding($holder, Purpose::SIGN_IN))->passed);
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Enums\FailureReason  $reason
     * @param  \Closure(): mixed  $operation
     * @return void
     */
    private function assertRefused(FailureReason $reason, \Closure $operation): void
    {
        try {
            $operation();
            self::fail(sprintf('The operation was expected to be refused with [%s].', $reason->value));
        } catch (OperationRefusedException $exception) {
            self::assertSame($reason, $exception->reason);
        }
    }
}
