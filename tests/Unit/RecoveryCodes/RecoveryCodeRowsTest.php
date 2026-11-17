<?php

declare(strict_types = 1);

namespace Tests\Unit\RecoveryCodes;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\ModelNotFoundException;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Exceptions\WriteCanceledException;
use SineMacula\Laravel\Mfa\Models\IdentityState;
use SineMacula\Laravel\Mfa\Models\RecoveryCode;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;
use SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeRows;
use Tests\Fixtures\Identities\TestUser;
use Tests\TestCase;

/**
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RecoveryCodeRows::class)]
final class RecoveryCodeRowsTest extends TestCase
{
    /**
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        CarbonImmutable::setTestNow('2026-11-01 08:00:00');
    }

    /**
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        CarbonImmutable::setTestNow();

        parent::tearDown();
    }

    /**
     * @return void
     */
    public function testAnOwnerWithoutAStateRowHasNoSet(): void
    {
        $status = $this->rows()->status($this->owner('none@example.test'));

        self::assertSame(0, $status->remaining);
        self::assertSame(0, $status->generation);
        self::assertNull($status->generatedAt);
    }

    /**
     * The earlier set is marked replaced, not deleted.
     *
     * @return void
     */
    public function testReplacingTheSetStoresTheHashesUnderTheNextGeneration(): void
    {
        $owner = $this->stateOwner('holder@example.test');

        self::assertSame(1, $this->rows()->replace($owner, ['hash-1', 'hash-2']));

        CarbonImmutable::setTestNow('2026-11-02 08:00:00');

        self::assertSame(2, $this->rows()->replace($owner, ['hash-3']));

        $codes    = RecoveryCode::query()->orderBy('code_hash')->get();
        $replaced = $codes->map(static fn (RecoveryCode $code): ?string => $code->replaced_at?->format('Y-m-d H:i:s'))->all();

        self::assertSame(['hash-1', 'hash-2', 'hash-3'], $codes->pluck('code_hash')->all());
        self::assertSame([1, 1, 2], $codes->pluck('generation')->all());
        self::assertSame([$owner->type], $codes->pluck('authenticatable_type')->unique()->values()->all());
        self::assertSame([$owner->key], $codes->pluck('authenticatable_id')->unique()->values()->all());
        self::assertSame(['2026-11-02 08:00:00', '2026-11-02 08:00:00', null], $replaced);

        $status = $this->rows()->status($owner);

        self::assertSame(1, $status->remaining);
        self::assertSame(2, $status->generation);
        self::assertSame('2026-11-02 08:00:00', $status->generatedAt?->format('Y-m-d H:i:s'));
    }

    /**
     * Not a used code, nor another owner's.
     *
     * @return void
     */
    public function testTheStatusCountsTheOwnersUsableCodes(): void
    {
        $owner = $this->stateOwner('holder@example.test');

        $this->rows()->replace($owner, ['hash-1', 'hash-2', 'hash-3']);
        $this->rows()->replace($this->stateOwner('other@example.test'), ['hash-4']);
        $this->rows()->markUsed($this->rows()->usable($owner)->firstOrFail());

        self::assertSame(2, $this->rows()->status($owner)->remaining);
    }

    /**
     * Of the current set only, unused.
     *
     * @return void
     */
    public function testTheUsableCodesAreTheCurrentSetsUnusedOnes(): void
    {
        $owner = $this->stateOwner('holder@example.test');

        $this->rows()->replace($owner, ['hash-1']);
        $this->rows()->replace($owner, ['hash-2', 'hash-3']);
        $this->rows()->replace($this->stateOwner('other@example.test'), ['hash-4']);

        $used = RecoveryCode::query()->where('code_hash', 'hash-2')->firstOrFail();

        $this->rows()->markUsed($used);

        self::assertSame(['hash-3'], $this->rows()->usable($owner)->pluck('code_hash')->all());
    }

    /**
     * Nor a replaced one.
     *
     * @return void
     */
    public function testACodeIsMarkedUsedOnce(): void
    {
        $owner = $this->stateOwner('holder@example.test');

        $this->rows()->replace($owner, ['hash-1']);

        $replaced = RecoveryCode::query()->where('code_hash', 'hash-1')->firstOrFail();

        $this->rows()->replace($owner, ['hash-2']);

        $code = RecoveryCode::query()->where('code_hash', 'hash-2')->firstOrFail();

        self::assertTrue($this->rows()->markUsed($code));
        self::assertFalse($this->rows()->markUsed($code));
        self::assertFalse($this->rows()->markUsed($replaced));
        self::assertSame('2026-11-01 08:00:00', $code->refresh()->used_at?->format('Y-m-d H:i:s'));
    }

    /**
     * Its codes are deleted and its time cleared; another owner's are kept.
     *
     * @return void
     */
    public function testDeletingASetReportsIt(): void
    {
        $owner = $this->stateOwner('holder@example.test');
        $other = $this->stateOwner('other@example.test');

        $this->rows()->replace($owner, ['hash-1', 'hash-2']);
        $this->rows()->replace($other, ['hash-3']);

        self::assertTrue($this->rows()->delete($owner));
        self::assertSame(['hash-3'], RecoveryCode::query()->pluck('code_hash')->all());
        self::assertNull($this->stateOf($owner)->recovery_codes_generated_at);
        self::assertFalse($this->rows()->delete($owner));
    }

    /**
     * A set whose time was already cleared still had one.
     *
     * @return void
     */
    public function testDeletingStrayCodesReportsASet(): void
    {
        $owner = $this->stateOwner('holder@example.test');

        $this->rows()->replace($owner, ['hash-1']);

        IdentityState::query()->update(['recovery_codes_generated_at' => null]);

        self::assertTrue($this->rows()->delete($owner));
        self::assertSame(0, RecoveryCode::query()->count());
    }

    /**
     * Codes used or replaced at or after it, and usable ones, are kept.
     *
     * @return void
     */
    public function testPruningDeletesCodesThatEndedBeforeTheCutoff(): void
    {
        $owner = $this->stateOwner('holder@example.test');

        $this->rows()->replace($owner, ['replaced']);
        $this->rows()->replace($owner, ['used', 'used-at-cutoff', 'usable']);

        $this->rows()->markUsed(RecoveryCode::query()->where('code_hash', 'used')->firstOrFail());

        CarbonImmutable::setTestNow('2026-11-02 08:00:00');

        $this->rows()->markUsed(RecoveryCode::query()->where('code_hash', 'used-at-cutoff')->firstOrFail());

        self::assertSame(2, $this->rows()->prune(CarbonImmutable::now()));
        self::assertSame(['usable', 'used-at-cutoff'], RecoveryCode::query()->orderBy('code_hash')->pluck('code_hash')->all());
    }

    /**
     * The caller's factor state lock creates it.
     *
     * @return void
     */
    public function testAWriteNeedsTheOwnersStateRow(): void
    {
        $this->expectException(ModelNotFoundException::class);

        $this->rows()->replace($this->owner('none@example.test'), ['hash-1']);
    }

    /**
     * @return void
     */
    public function testACanceledCodeSaveThrows(): void
    {
        $owner = $this->stateOwner('holder@example.test');

        RecoveryCode::saving(static fn (): bool => false);

        $this->expectException(WriteCanceledException::class);
        $this->expectExceptionMessage(sprintf('A model event cancelled the save of a [%s], so the change it is part of was rolled back.', RecoveryCode::class));

        $this->rows()->replace($owner, ['hash-1']);
    }

    /**
     * @return void
     */
    public function testACanceledStateSaveThrows(): void
    {
        $owner = $this->stateOwner('holder@example.test');

        $this->rows()->replace($owner, ['hash-1']);

        IdentityState::saving(static fn (): bool => false);

        $this->expectException(WriteCanceledException::class);
        $this->expectExceptionMessage(IdentityState::class);

        $this->rows()->delete($owner);
    }

    /**
     * @return \SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeRows
     */
    private function rows(): RecoveryCodeRows
    {
        return new RecoveryCodeRows(config());
    }

    /**
     * @param  string  $email
     * @return \SineMacula\Laravel\Mfa\Proofs\ProofOwner
     */
    private function owner(string $email): ProofOwner
    {
        return ProofOwner::of(TestUser::query()->create(['email' => $email]));
    }

    /**
     * An owner with the state row its factor state lock would create.
     *
     * @param  string  $email
     * @return \SineMacula\Laravel\Mfa\Proofs\ProofOwner
     */
    private function stateOwner(string $email): ProofOwner
    {
        $owner = $this->owner($email);

        IdentityState::query()->create(['authenticatable_type' => $owner->type, 'authenticatable_id' => $owner->key]);

        return $owner;
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofOwner  $owner
     * @return \SineMacula\Laravel\Mfa\Models\IdentityState
     */
    private function stateOf(ProofOwner $owner): IdentityState
    {
        return IdentityState::query()->where('authenticatable_type', $owner->type)->where('authenticatable_id', $owner->key)->firstOrFail();
    }
}
