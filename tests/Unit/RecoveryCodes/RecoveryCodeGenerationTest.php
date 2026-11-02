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
use Tests\Fixtures\Exceptions\MidRotationFailureException;
use Tests\Fixtures\Identities\FactorHolder;
use Tests\Fixtures\Identities\NonEloquentIdentity;
use Tests\TestCase;
use Tests\Unit\Concerns\InteractsWithRecoveryCodes;

/**
 * Tests for generating a recovery code set: the codes come back once, as
 * secrets, and are stored only as salted hashes made with the application's
 * hasher; a new set replaces the old one atomically, so there is never a moment
 * when both work or neither exists; and generation is refused unless the
 * application accepts recovery codes and the identity, a person who is active,
 * has a confirmed factor.
 *
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
     * A set of the configured size comes back as secrets, unformatted, drawn
     * from the configured alphabet: a secret refuses to be encoded on its own,
     * and the response helper reveals each one.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testReturnsTheSetOnceAsSecrets(): void
    {
        $holder = $this->signInHolder();
        $codes  = $this->recoveryCodes()->generate($holder);

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
     * The configured count, length and alphabet govern the set.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheConfiguredSettingsGovernTheSet(): void
    {
        config()->set('mfa.recovery_codes', ['count' => 3, 'length' => 16, 'alphabet' => 'abcdefghjk']);

        $codes = self::plaintexts($this->recoveryCodes()->generate($this->signInHolder()));

        self::assertCount(3, $codes);

        foreach ($codes as $code) {
            self::assertMatchesRegularExpression('/^[ABCDEFGHJK]{16}$/', $code);
        }
    }

    /**
     * Each code is stored only as a salted hash the application's hasher
     * accepts, never in plaintext, under the first generation, usable; the
     * identity's state row records the generation and its time.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testStoresEachCodeAsASaltedHash(): void
    {
        $this->travelTo(CarbonImmutable::parse('2026-11-01 09:30:00'));

        $holder = $this->signInHolder();
        $codes  = self::plaintexts($this->recoveryCodes()->generate($holder));
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
     * The codes are hashed with the hashing driver the application configures,
     * as its passwords are.
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

        $this->recoveryCodes()->generate($holder);

        foreach ($this->storedCodes($holder) as $row) {
            self::assertSame('argon2id', password_get_info((string) $row->getCodeHash())['algoName']);
        }
    }

    /**
     * A new set replaces the old one: every earlier code, used or not, is
     * marked replaced at the time of the new set, the generation advances, and
     * the earlier codes no longer redeem while the new ones do.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testANewSetReplacesTheOldOne(): void
    {
        $holder   = $this->signInHolder();
        $previous = self::plaintexts($this->recoveryCodes()->generate($holder));

        self::assertTrue($this->recoveryCodes()->redeem($holder, $previous[0], self::redemptionBinding($holder, Purpose::STEP_UP))->passed);

        $this->travelTo(CarbonImmutable::parse('2026-11-02 10:00:00'));

        $current = self::plaintexts($this->recoveryCodes()->generate($holder));

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
     * Another identity's set is left alone.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testOnlyTheIdentitysOwnSetIsReplaced(): void
    {
        $neighbor = FactorHolder::query()->create(['email' => 'neighbor@example.com']);

        $this->addFactor($neighbor);
        $this->recoveryCodes()->generate($neighbor);

        $this->recoveryCodes()->generate($this->signInHolder());

        self::assertCount(10, $this->storedCodes($neighbor)->filter(static fn (RecoveryCode $row): bool => $row->isUsable()));
    }

    /**
     * `RecoveryCodesGenerated` is dispatched once, after the commit, with the
     * set's size, its generation and the actor, and never a code.
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

        $codes = self::plaintexts($this->recoveryCodes()->generate($holder, $actor));

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
     * A failure partway through the replacement rolls all of it back: the
     * previous set still redeems, the generation is unchanged, no partial set
     * remains and nothing is reported.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFailedReplacementKeepsThePreviousSet(): void
    {
        $holder   = $this->signInHolder();
        $previous = self::plaintexts($this->recoveryCodes()->generate($holder));
        $inserted = 0;

        RecoveryCode::creating(static function () use (&$inserted): void {
            if (++$inserted === 4) {
                throw new MidRotationFailureException('Failed mid-replacement.');
            }
        });

        Event::fake([RecoveryCodesGenerated::class]);

        try {
            $this->recoveryCodes()->generate($holder);
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
     * A replacement whose code insert a model event cancels, without throwing,
     * throws instead of committing a partial set: the previous set still
     * redeems, the generation is unchanged and nothing is reported.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACanceledCodeSaveKeepsThePreviousSet(): void
    {
        $holder   = $this->signInHolder();
        $previous = self::plaintexts($this->recoveryCodes()->generate($holder));
        $inserted = 0;

        RecoveryCode::creating(static function () use (&$inserted): bool {
            return ++$inserted !== 4;
        });

        $this->assertReplacementCanceled($holder, $previous, RecoveryCode::class);
    }

    /**
     * A replacement whose state row save a model event cancels throws instead
     * of committing a set its state row does not record.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACanceledStateSaveKeepsThePreviousSet(): void
    {
        $holder   = $this->signInHolder();
        $previous = self::plaintexts($this->recoveryCodes()->generate($holder));

        IdentityState::saving(static fn (): bool => false);

        $this->assertReplacementCanceled($holder, $previous, IdentityState::class);
    }

    /**
     * Inside the replacement, the earlier codes are already replaced when the
     * first new code is stored, and the new codes are stored under the next
     * generation before it is recorded, so the set a redemption reads under the
     * same lock is the old one or the new one, never both.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheOldSetIsReplacedBeforeTheNewOneIsStored(): void
    {
        $holder = $this->signInHolder();

        $this->recoveryCodes()->generate($holder);

        $usable = [];

        RecoveryCode::creating(function () use ($holder, &$usable): void {
            $usable[] = $this->storedCodes($holder)->filter(static fn (RecoveryCode $row): bool => $row->isUsable())->count();
        });

        $this->recoveryCodes()->generate($holder);

        self::assertSame(range(0, 9), $usable);
    }

    /**
     * Generation is refused, and nothing written, when the application does not
     * accept recovery codes.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRefusedWhenTheApplicationDoesNotAcceptRecoveryCodes(): void
    {
        config()->set('mfa.applications.web.recovery_codes.enabled', false);

        $holder = $this->signInHolder();

        $this->assertRefused(FailureReason::TYPE_NOT_ENABLED, fn () => $this->recoveryCodes()->generate($holder));

        self::assertCount(0, $this->storedCodes($holder));
    }

    /**
     * Generation is refused for an identity whose only factor is pending, and
     * for one with none.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRefusedWithoutAConfirmedFactor(): void
    {
        $pending = $this->signInHolder('pending@example.com', 'pending');
        $none    = $this->signInHolder('none@example.com', null);

        $this->assertRefused(FailureReason::NO_FACTOR, fn () => $this->recoveryCodes()->generate($pending));
        $this->assertRefused(FailureReason::NO_FACTOR, fn () => $this->recoveryCodes()->generate($none));

        self::assertCount(0, $this->storedCodes($pending));
    }

    /**
     * Generation checks the confirmed factor again under the lock, so an
     * identity whose own answer counts a pending factor is still refused, and
     * nothing is written.
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

        $this->assertRefused(FailureReason::NO_FACTOR, fn () => $this->recoveryCodes()->generate($identity));

        self::assertSame(0, RecoveryCode::query()->where('authenticatable_id', 'pending-only')->count());
    }

    /**
     * A machine identity and an inactive one are refused.
     *
     * @return void
     */
    public function testRefusedForAMachineOrInactiveIdentity(): void
    {
        $this->assertRefused(FailureReason::MACHINE_IDENTITY, fn () => $this->recoveryCodes()->generate(new NonEloquentIdentity('machine', mfaEnabled: true, person: false)));
        $this->assertRefused(FailureReason::IDENTITY_INACTIVE, fn () => $this->recoveryCodes()->generate(new NonEloquentIdentity('inactive', mfaEnabled: true, active: false)));
    }

    /**
     * Recovery codes are not a factor: an identity holding a set but no
     * confirmed factor is not set up.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRecoveryCodesDoNotCountAsAFactor(): void
    {
        $holder = $this->signInHolder();
        $factor = $holder->authFactors()->firstOrFail();

        $this->recoveryCodes()->generate($holder);

        $factor->delete();

        self::assertCount(10, $this->storedCodes($holder));
        self::assertFalse($holder->isMfaEnabled());
        self::assertSame([], Mfa::factors());
    }

    /**
     * Assert a new set for the holder throws because a save of the given model
     * was cancelled, and leaves the previous set in place: its codes stored and
     * usable, the generation unchanged, nothing reported, and a code of it
     * still redeeming.
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
            $this->recoveryCodes()->generate($holder);
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
     * Assert the operation is refused with the given reason.
     *
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
