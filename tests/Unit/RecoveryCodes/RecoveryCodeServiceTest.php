<?php

declare(strict_types = 1);

namespace Tests\Unit\RecoveryCodes;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Events\Actor;
use SineMacula\Laravel\Mfa\Events\RecoveryCodesGenerated;
use SineMacula\Laravel\Mfa\Events\RecoveryCodesLow;
use SineMacula\Laravel\Mfa\Events\RecoveryCodesRemoved;
use SineMacula\Laravel\Mfa\Events\RecoveryCodeUsed;
use SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException;
use SineMacula\Laravel\Mfa\Exceptions\WriteCanceledException;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Models\IdentityState;
use SineMacula\Laravel\Mfa\Models\RecoveryCode;
use SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeService;
use SineMacula\Laravel\Mfa\Support\FactorStateTransaction;
use Tests\Fixtures\Identities\FactorHolder;
use Tests\TestCase;
use Tests\Unit\Concerns\InteractsWithRecoveryCodes;

/**
 * Tests for where a recovery code set stands, how it is removed with the last
 * factor, and how used and replaced codes are pruned: the remaining count and
 * the set's time are read without a code, in one statement, of the current set
 * only; removal runs inside the identity's factor state transaction and reports
 * a set that existed; pruning deletes only codes that can no longer be
 * redeemed.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RecoveryCodeService::class)]
final class RecoveryCodeServiceTest extends TestCase
{
    use InteractsWithRecoveryCodes;

    /**
     * An identity that never had a set has none: nothing remaining, no
     * generation and no time.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnIdentityWithoutASetHasNone(): void
    {
        $status = $this->recoveryCodes()->status($this->signInHolder());

        self::assertSame(0, $status->remaining);
        self::assertSame(0, $status->generation);
        self::assertNull($status->generatedAt);
        self::assertFalse($status->exists());
    }

    /**
     * The status follows the set: its size and time once generated, one less
     * per redemption, which passes and says so, the next generation's size and
     * time once replaced, and only the identity's own codes.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheStatusFollowsTheCurrentSet(): void
    {
        $this->travelTo(CarbonImmutable::parse('2026-11-01 08:00:00'));

        $neighbor = FactorHolder::query()->create(['email' => 'neighbor@example.com']);

        $this->addFactor($neighbor);
        $this->recoveryCodes()->generate($neighbor, 'web');

        $holder = $this->signInHolder();
        $codes  = self::plaintexts($this->recoveryCodes()->generate($holder, 'web'));
        $status = $this->recoveryCodes()->status($holder);

        self::assertSame(10, $status->remaining);
        self::assertSame(1, $status->generation);
        self::assertSame('2026-11-01 08:00:00', $status->generatedAt?->format('Y-m-d H:i:s'));
        self::assertTrue($status->exists());

        $first  = $this->recoveryCodes()->redeem($holder, $codes[0], self::redemptionBinding($holder, Purpose::SIGN_IN));
        $second = $this->recoveryCodes()->redeem($holder, $codes[1], self::redemptionBinding($holder, Purpose::SIGN_IN));

        self::assertTrue($first->passed);
        self::assertSame(9, $first->remaining);
        self::assertTrue($second->passed);
        self::assertSame(8, $second->remaining);
        self::assertSame(8, $this->recoveryCodes()->status($holder)->remaining);

        $this->travelTo(CarbonImmutable::parse('2026-11-03 08:00:00'));

        $this->recoveryCodes()->generate($holder, 'web');

        $status = $this->recoveryCodes()->status($holder);

        self::assertSame(10, $status->remaining);
        self::assertSame(2, $status->generation);
        self::assertSame('2026-11-03 08:00:00', $status->generatedAt?->format('Y-m-d H:i:s'));
    }

    /**
     * The status is read in one statement, so the count and the generation are
     * always of the same set.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheStatusIsReadInOneStatement(): void
    {
        $holder = $this->signInHolder();

        $this->recoveryCodes()->generate($holder, 'web');

        $statements = 0;

        DB::listen(static function () use (&$statements): void {
            $statements++;
        });

        $this->recoveryCodes()->status($holder);

        self::assertSame(1, $statements);
    }

    /**
     * A used-up set still exists, with nothing remaining.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAUsedUpSetKeepsItsTime(): void
    {
        config()->set('mfa.recovery_codes.count', 2);
        config()->set('mfa.recovery_codes.low_count', 1);

        $holder = $this->signInHolder();

        foreach (self::plaintexts($this->recoveryCodes()->generate($holder, 'web')) as $code) {
            $this->recoveryCodes()->redeem($holder, $code, self::redemptionBinding($holder, Purpose::SIGN_IN));
        }

        $status = $this->recoveryCodes()->status($holder);

        self::assertSame(0, $status->remaining);
        self::assertSame(1, $status->generation);
        self::assertTrue($status->exists());
    }

    /**
     * Deleting the set reports nothing and says it existed; reporting it is its
     * own call, once the set's removal is ready to be told.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testDeletingTheSetReportsNothingUntilItIsAsked(): void
    {
        $holder = $this->signInHolder();

        $this->recoveryCodes()->generate($holder, 'web');

        Event::fake([RecoveryCodesRemoved::class]);

        self::assertTrue(FactorStateTransaction::forIdentity($holder, new Factor, fn (): bool => $this->recoveryCodes()->deleteSet($holder)));
        self::assertCount(0, $this->storedCodes($holder));
        self::assertNull($this->stateOf($holder)->recovery_codes_generated_at);

        Event::assertNotDispatched(RecoveryCodesRemoved::class);

        self::assertFalse(FactorStateTransaction::forIdentity($holder, new Factor, fn (): bool => $this->recoveryCodes()->deleteSet($holder)));

        $actor = new Actor('admin', '9');

        $this->recoveryCodes()->reportSetRemoved($holder, $actor);

        Event::assertDispatchedTimes(RecoveryCodesRemoved::class, 1);
        Event::assertDispatched(RecoveryCodesRemoved::class, static fn (RecoveryCodesRemoved $event): bool => $event->actor === $actor);
    }

    /**
     * Removing the set deletes every code row, clears the set's time, keeps its
     * generation, and reports the removal with the actor once it commits.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRemovingTheSetDeletesItAndReportsIt(): void
    {
        $holder = $this->signInHolder();
        $actor  = new Actor('admin', '9');

        $this->recoveryCodes()->generate($holder, 'web');
        $this->recoveryCodes()->generate($holder, 'web');

        Event::fake([RecoveryCodesRemoved::class]);

        self::assertTrue($this->removeSet($holder, $actor));
        self::assertCount(0, $this->storedCodes($holder));
        self::assertNull($this->stateOf($holder)->recovery_codes_generated_at);
        self::assertSame(2, $this->stateOf($holder)->recovery_codes_generation);
        self::assertFalse($this->recoveryCodes()->status($holder)->exists());

        Event::assertDispatchedTimes(RecoveryCodesRemoved::class, 1);
        Event::assertDispatched(RecoveryCodesRemoved::class, static fn (RecoveryCodesRemoved $event): bool => $event->actor === $actor);
    }

    /**
     * A used-up set whose codes were all pruned is still a set, and its removal
     * is reported; so are code rows left without a set's time.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPrunedSetOrStrayRowsStillReportARemoval(): void
    {
        $holder = $this->signInHolder();

        $this->recoveryCodes()->generate($holder, 'web');

        RecoveryCode::query()->delete();

        Event::fake([RecoveryCodesRemoved::class]);

        self::assertTrue($this->removeSet($holder));

        RecoveryCode::query()->create([
            'authenticatable_type' => $holder->getMorphClass(),
            'authenticatable_id'   => (string) $holder->id,
            'code_hash'            => 'stray-hash',
            'generation'           => 1,
        ]);

        self::assertTrue($this->removeSet($holder));
        self::assertCount(0, $this->storedCodes($holder));

        Event::assertDispatchedTimes(RecoveryCodesRemoved::class, 2);
    }

    /**
     * Without a set there is nothing to remove, and nothing is reported.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testWithoutASetNothingIsRemoved(): void
    {
        $holder = $this->signInHolder();

        Event::fake([RecoveryCodesRemoved::class]);

        self::assertFalse($this->removeSet($holder));

        Event::assertNotDispatched(RecoveryCodesRemoved::class);
    }

    /**
     * A removal whose state row save a model event cancels throws, so the whole
     * removal rolls back: every code row stays, the set's time is kept and
     * nothing is reported.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACanceledStateSaveRollsTheRemovalBack(): void
    {
        $holder = $this->signInHolder();

        $this->recoveryCodes()->generate($holder, 'web');

        IdentityState::saving(static fn (): bool => false);

        Event::fake([RecoveryCodesRemoved::class]);

        $thrown = null;

        try {
            $this->removeSet($holder);
        } catch (WriteCanceledException $exception) {
            $thrown = $exception;
        }

        self::assertInstanceOf(WriteCanceledException::class, $thrown);
        self::assertStringContainsString(IdentityState::class, $thrown->getMessage());

        self::assertCount(10, $this->storedCodes($holder));
        self::assertNotNull($this->stateOf($holder)->recovery_codes_generated_at);
        Event::assertNotDispatched(RecoveryCodesRemoved::class);
    }

    /**
     * Removing a set outside the identity's factor state transaction is
     * refused, as it would not be atomic with the factor's removal.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRemovingASetOutsideTheTransactionIsRefused(): void
    {
        $holder = $this->signInHolder();

        $this->recoveryCodes()->generate($holder, 'web');

        try {
            $this->recoveryCodes()->removeSet($holder);
            self::fail('Removing a set outside the transaction was expected to be refused.');
        } catch (\LogicException $exception) {
            self::assertSame('A recovery code set is removed only inside the identity\'s factor state transaction.', $exception->getMessage());
        }

        self::assertCount(10, $this->storedCodes($holder));
    }

    /**
     * Pruning deletes the codes used or replaced before the cutoff and keeps
     * every usable code, every code used or replaced since, and the identity's
     * state row; it returns how many it deleted.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testPruningDeletesOnlyCodesThatEndedBeforeTheCutoff(): void
    {
        config()->set('mfa.recovery_codes.count', 3);

        $this->travelTo(CarbonImmutable::parse('2026-10-01 00:00:00'));

        $holder = $this->signInHolder();
        $first  = self::plaintexts($this->recoveryCodes()->generate($holder, 'web'));

        $this->recoveryCodes()->redeem($holder, $first[0], self::redemptionBinding($holder, Purpose::SIGN_IN));

        $this->travelTo(CarbonImmutable::parse('2026-10-10 00:00:00'));

        $second = self::plaintexts($this->recoveryCodes()->generate($holder, 'web'));

        $this->travelTo(CarbonImmutable::parse('2026-10-20 00:00:00'));

        $this->recoveryCodes()->redeem($holder, $second[0], self::redemptionBinding($holder, Purpose::SIGN_IN));

        self::assertSame(3, $this->recoveryCodes()->prune(CarbonImmutable::parse('2026-10-15 00:00:00')));

        $kept = $this->storedCodes($holder);

        self::assertCount(3, $kept);
        self::assertTrue($kept->every(static fn (RecoveryCode $row): bool => $row->getAttribute($row->getGenerationName()) === 2));
        self::assertCount(2, $kept->filter(static fn (RecoveryCode $row): bool => $row->isUsable()));
        self::assertSame(2, $this->recoveryCodes()->status($holder)->remaining);
        self::assertTrue($this->recoveryCodes()->status($holder)->exists());

        self::assertSame(0, $this->recoveryCodes()->prune(CarbonImmutable::parse('2026-10-15 00:00:00')));
        self::assertSame(1, $this->recoveryCodes()->prune(CarbonImmutable::parse('2026-10-21 00:00:00')));
    }

    /**
     * Rows of the codes left after a redemption, the low count, and whether the
     * set is reported low.
     *
     * @return iterable<string, array{int, int, bool}>
     */
    public static function lowCounts(): iterable
    {
        yield 'above the low count' => [4, 3, false];
        yield 'at the low count' => [3, 3, true];
        yield 'below the low count' => [2, 3, true];
        yield 'none left' => [0, 3, true];
        yield 'no low count' => [0, 0, false];
    }

    /**
     * A redemption is always reported used, and low only when it leaves the set
     * at or below a low count that is set.
     *
     * @param  int  $remaining
     * @param  int  $lowCount
     * @param  bool  $low
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[DataProvider('lowCounts')]
    public function testARedemptionIsReportedLowAtOrBelowTheLowCount(int $remaining, int $lowCount, bool $low): void
    {
        config()->set('mfa.recovery_codes.low_count', $lowCount);

        Event::fake([RecoveryCodeUsed::class, RecoveryCodesLow::class]);

        $holder = $this->signInHolder();

        $this->recoveryCodes()->reportRedeemed($holder, self::redemptionBinding($holder), $remaining);

        Event::assertDispatchedTimes(RecoveryCodeUsed::class, 1);
        Event::assertDispatchedTimes(RecoveryCodesLow::class, $low ? 1 : 0);
    }

    /**
     * A gate runs before the codes are drawn, given no factors, and again first
     * under the lock, given the identity's factors as stored there; a refusal
     * before the lock replaces nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAGateRunsBeforeTheLockAndAgainUnderIt(): void
    {
        $holder   = $this->signInHolder();
        $previous = self::plaintexts($this->recoveryCodes()->generate($holder, 'web'));
        $asked    = [];

        $this->recoveryCodes()->generate($holder, 'web', null, static function (?Collection $factors) use (&$asked): void {
            $asked[] = $factors?->count();
        });

        self::assertSame([null, 1], $asked);

        $current = self::plaintexts($this->recoveryCodes()->generate($holder, 'web'));

        try {
            $this->recoveryCodes()->generate($holder, 'web', null, static function (?Collection $factors): void {
                OperationRefusedException::byPackageUnless($factors !== null, FailureReason::NOT_FRESH, 'Refused before the lock.');
            });
            self::fail('The gate was expected to refuse before the lock.');
        } catch (OperationRefusedException $exception) {
            self::assertSame('Refused before the lock.', $exception->getMessage());
        }

        self::assertNotSame($previous, $current);
        self::assertSame(count($current), RecoveryCode::query()->whereNull('replaced_at')->count());
    }

    /**
     * Replacing the set stores the next generation and returns its codes with
     * it, and reports nothing, which is left to the caller.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testReplacingTheSetReturnsItsGenerationAndReportsNothing(): void
    {
        Event::fake([RecoveryCodesGenerated::class]);

        $holder = $this->signInHolder();
        $set    = $this->recoveryCodes()->replaceSet($holder, 'web');

        self::assertSame(1, $set['generation']);
        self::assertCount(10, $set['codes']);
        self::assertSame(10, $this->recoveryCodes()->status($holder)->remaining);
        Event::assertNotDispatched(RecoveryCodesGenerated::class);
    }

    /**
     * Remove the identity's set as the removal of its last factor does: inside
     * its factor state transaction.
     *
     * @param  \Tests\Fixtures\Identities\FactorHolder  $holder
     * @param  ?\SineMacula\Laravel\Mfa\Events\Actor  $actor
     * @return bool
     *
     * @throws \Throwable
     */
    private function removeSet(FactorHolder $holder, ?Actor $actor = null): bool
    {
        return FactorStateTransaction::forIdentity($holder, new Factor, fn (): bool => $this->recoveryCodes()->removeSet($holder, $actor));
    }
}
