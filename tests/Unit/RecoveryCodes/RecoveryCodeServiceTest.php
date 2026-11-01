<?php

declare(strict_types = 1);

namespace Tests\Unit\RecoveryCodes;

use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Events\Actor;
use SineMacula\Laravel\Mfa\Events\RecoveryCodesRemoved;
use SineMacula\Laravel\Mfa\Exceptions\WriteCancelledException;
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
     * per redemption, the next generation's size and time once replaced, and
     * only the identity's own codes.
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
        $this->recoveryCodes()->generate($neighbor);

        $holder = $this->signInHolder();
        $codes  = self::plaintexts($this->recoveryCodes()->generate($holder));
        $status = $this->recoveryCodes()->status($holder);

        self::assertSame(10, $status->remaining);
        self::assertSame(1, $status->generation);
        self::assertSame('2026-11-01 08:00:00', $status->generatedAt?->format('Y-m-d H:i:s'));
        self::assertTrue($status->exists());

        $this->recoveryCodes()->redeem($holder, $codes[0], Purpose::SIGN_IN);
        $this->recoveryCodes()->redeem($holder, $codes[1], Purpose::SIGN_IN);

        self::assertSame(8, $this->recoveryCodes()->status($holder)->remaining);

        $this->travelTo(CarbonImmutable::parse('2026-11-03 08:00:00'));

        $this->recoveryCodes()->generate($holder);

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

        $this->recoveryCodes()->generate($holder);

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

        foreach (self::plaintexts($this->recoveryCodes()->generate($holder)) as $code) {
            $this->recoveryCodes()->redeem($holder, $code, Purpose::SIGN_IN);
        }

        $status = $this->recoveryCodes()->status($holder);

        self::assertSame(0, $status->remaining);
        self::assertSame(1, $status->generation);
        self::assertTrue($status->exists());
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

        $this->recoveryCodes()->generate($holder);
        $this->recoveryCodes()->generate($holder);

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

        $this->recoveryCodes()->generate($holder);

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
    public function testACancelledStateSaveRollsTheRemovalBack(): void
    {
        $holder = $this->signInHolder();

        $this->recoveryCodes()->generate($holder);

        IdentityState::saving(static fn (): bool => false);

        Event::fake([RecoveryCodesRemoved::class]);

        $thrown = null;

        try {
            $this->removeSet($holder);
        } catch (WriteCancelledException $exception) {
            $thrown = $exception;
        }

        self::assertInstanceOf(WriteCancelledException::class, $thrown);
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

        $this->recoveryCodes()->generate($holder);

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
        $first  = self::plaintexts($this->recoveryCodes()->generate($holder));

        $this->recoveryCodes()->redeem($holder, $first[0], Purpose::SIGN_IN);

        $this->travelTo(CarbonImmutable::parse('2026-10-10 00:00:00'));

        $second = self::plaintexts($this->recoveryCodes()->generate($holder));

        $this->travelTo(CarbonImmutable::parse('2026-10-20 00:00:00'));

        $this->recoveryCodes()->redeem($holder, $second[0], Purpose::SIGN_IN);

        self::assertSame(3, $this->recoveryCodes()->prune(CarbonImmutable::parse('2026-10-15 00:00:00')));

        $kept = $this->storedCodes($holder);

        self::assertCount(3, $kept);
        self::assertTrue($kept->every(static fn (RecoveryCode $row): bool => $row->getGeneration() === 2));
        self::assertCount(2, $kept->filter(static fn (RecoveryCode $row): bool => $row->isUsable()));
        self::assertSame(2, $this->recoveryCodes()->status($holder)->remaining);
        self::assertTrue($this->recoveryCodes()->status($holder)->exists());

        self::assertSame(0, $this->recoveryCodes()->prune(CarbonImmutable::parse('2026-10-15 00:00:00')));
        self::assertSame(1, $this->recoveryCodes()->prune(CarbonImmutable::parse('2026-10-21 00:00:00')));
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
