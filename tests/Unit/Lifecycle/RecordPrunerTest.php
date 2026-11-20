<?php

declare(strict_types = 1);

namespace Tests\Unit\Lifecycle;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Lifecycle\RecordPruner;
use SineMacula\Laravel\Mfa\Models\Code;
use Tests\Fixtures\Lifecycle\Concerns\ArrangesLifecycle;
use Tests\TestCase;

/**
 * Run in Europe/London in November with 30 days of retention, so the cutoff
 * falls before the clocks went back.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RecordPruner::class)]
final class RecordPrunerTest extends TestCase
{
    use ArrangesLifecycle;

    /**
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->arrangeLifecycle();
        $this->useTimezone('Europe/London');

        config()->set('mfa.lifecycle.prune_after_days', 30);

        CarbonImmutable::setTestNow(CarbonImmutable::parse('2026-11-20 12:00:00', 'UTC'));
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
     * Half an hour either side of the cutoff, 30 days of 24 hours back, which
     * counting back on the wall clock would put an hour earlier.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testCodesAndEnrollmentsAreCutOffAtTheInstant(): void
    {
        $user   = $this->signedInPerson();
        $cutoff = CarbonImmutable::parse('2026-10-21 12:00:00', 'UTC');

        [$expired]   = $this->pendingEnrollmentOf($user, $cutoff->subMinutes(30));
        [$retained]  = $this->pendingEnrollmentOf($user, $cutoff->addMinutes(30));
        $expiredCode = $this->codeOf($user->id, $cutoff->subMinutes(30));
        $kept        = $this->codeOf($user->id, $cutoff->addMinutes(30));

        $result = $this->container()->make(RecordPruner::class)();

        self::assertSame(1, $result->enrollments);
        self::assertSame(1, $result->codes);
        self::assertFalse($this->isStored($expired));
        self::assertTrue($this->isStored($retained));
        self::assertFalse(Code::query()->whereKey($expiredCode->id)->exists());
        self::assertTrue(Code::query()->whereKey($kept->id)->exists());
    }

    /**
     * @param  int  $userId
     * @param  \Carbon\CarbonImmutable  $expiresAt
     * @return \SineMacula\Laravel\Mfa\Models\Code
     */
    private function codeOf(int $userId, CarbonImmutable $expiresAt): Code
    {
        /** @var \SineMacula\Laravel\Mfa\Models\Code */
        return Code::query()->create([
            'factor_id'            => 'factor',
            'authenticatable_type' => 'users',
            'authenticatable_id'   => (string) $userId,
            'purpose'              => 'sign_in',
            'application'          => 'web',
            'code_hash'            => 'code',
            'attempts'             => 0,
            'sends'                => 1,
            'sent_at'              => $expiresAt,
            'expires_at'           => $expiresAt,
        ]);
    }
}
