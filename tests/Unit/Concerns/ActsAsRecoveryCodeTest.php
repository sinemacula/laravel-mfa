<?php

declare(strict_types = 1);

namespace Tests\Unit\Concerns;

use Carbon\Carbon;
use Illuminate\Database\Eloquent\Relations\MorphTo;
use Illuminate\Foundation\Testing\RefreshDatabase;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Mfa\Concerns\ActsAsRecoveryCode;
use SineMacula\Laravel\Mfa\Contracts\RecoveryCode as RecoveryCodeContract;
use SineMacula\Laravel\Mfa\Models\RecoveryCode;
use Tests\Fixtures\Identities\TestUser;
use Tests\TestCase;

/**
 * Unit tests for the `ActsAsRecoveryCode` trait: a recovery code's owner, hash,
 * generation, use and replacement, and the column names it reads them from.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversTrait(ActsAsRecoveryCode::class)]
final class ActsAsRecoveryCodeTest extends TestCase
{
    use RefreshDatabase;

    /**
     * Clear the frozen clock.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Carbon::setTestNow();

        parent::tearDown();
    }

    /**
     * The shipped model implements the contract, with the trait's column names.
     *
     * @return void
     */
    public function testNamesItsColumns(): void
    {
        $code = new RecoveryCode;

        self::assertInstanceOf(RecoveryCodeContract::class, $code);
        self::assertSame('code_hash', $code->getCodeHashName());
        self::assertSame('generation', $code->getGenerationName());
        self::assertSame('used_at', $code->getUsedAtName());
        self::assertSame('replaced_at', $code->getReplacedAtName());
    }

    /**
     * A stored code reads back its owner, hash and generation, and is usable
     * until it is used or replaced.
     *
     * @return void
     */
    public function testReadsBackAStoredCode(): void
    {
        $user = TestUser::query()->create(['email' => 'alice@example.test', 'mfa_enabled' => true]);

        $stored = RecoveryCode::query()->create([
            'authenticatable_type' => $user->getMorphClass(),
            'authenticatable_id'   => (string) $user->id,
            'code_hash'            => '$2y$hash',
            'generation'           => 3,
        ]);

        $code = RecoveryCode::query()->findOrFail($stored->id);

        self::assertSame('$2y$hash', $code->getCodeHash());
        self::assertSame(3, $code->getAttribute($code->getGenerationName()));
        self::assertNull($code->getUsedAt());
        self::assertNull($code->getReplacedAt());
        self::assertTrue($code->isUsable());
        self::assertInstanceOf(MorphTo::class, $code->authenticatable());
        self::assertTrue($user->is($code->authenticatable()->first()));
    }

    /**
     * Using a code, at the given time or now, or replacing its set, ends it.
     *
     * @return void
     */
    public function testUsingOrReplacingACodeEndsIt(): void
    {
        Carbon::setTestNow('2026-04-15T10:00:00+00:00');

        $used = new RecoveryCode;
        $used->markUsed();

        self::assertSame('2026-04-15T10:00:00+00:00', $used->getUsedAt()?->toIso8601String());
        self::assertFalse($used->isUsable());

        $replaced = new RecoveryCode;
        $replaced->setAttribute($replaced->getReplacedAtName(), Carbon::parse('2026-04-14T08:00:00+00:00'));

        self::assertSame('2026-04-14T08:00:00+00:00', $replaced->getReplacedAt()?->toIso8601String());
        self::assertNull($replaced->getUsedAt());
        self::assertFalse($replaced->isUsable());

        $usedThen = new RecoveryCode;
        $usedThen->markUsed(Carbon::parse('2026-04-14T08:00:00+00:00'));

        self::assertSame('2026-04-14T08:00:00+00:00', $usedThen->getUsedAt()?->toIso8601String());
    }

    /**
     * A value of the wrong type reads as absent.
     *
     * @return void
     */
    public function testAValueOfTheWrongTypeReadsAsAbsent(): void
    {
        $code = new class extends RecoveryCode {
            /**
             * Cast nothing, so the raw values are read as they are.
             *
             * @return array<string, string>
             */
            #[\Override]
            protected function casts(): array
            {
                return [];
            }
        };

        $code->setRawAttributes(['code_hash' => 5, 'used_at' => '2026-04-15', 'replaced_at' => '2026-04-15']);

        self::assertNull($code->getCodeHash());
        self::assertNull($code->getUsedAt());
        self::assertNull($code->getReplacedAt());
        self::assertTrue($code->isUsable());
    }
}
