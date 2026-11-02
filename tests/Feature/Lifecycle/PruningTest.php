<?php

declare(strict_types = 1);

namespace Tests\Feature\Lifecycle;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Console\Kernel;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Attempts\AttemptStore;
use SineMacula\Laravel\Mfa\Console\PruneCommand;
use SineMacula\Laravel\Mfa\Database\BoundedDelete;
use SineMacula\Laravel\Mfa\Enums\AttemptScope;
use SineMacula\Laravel\Mfa\Events\EnrollmentExpired;
use SineMacula\Laravel\Mfa\Events\EventDispatcher;
use SineMacula\Laravel\Mfa\Exceptions\WriteCancelledException;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\Lifecycle\PruneResult;
use SineMacula\Laravel\Mfa\Lifecycle\RecordPruner;
use SineMacula\Laravel\Mfa\MfaManager;
use SineMacula\Laravel\Mfa\Models\Code;
use SineMacula\Laravel\Mfa\Models\Enrollment;
use SineMacula\Laravel\Mfa\Models\RecoveryCode;
use Tests\Fixtures\Identities\TestUser;
use Tests\Fixtures\Lifecycle\Concerns\ArrangesLifecycle;
use Tests\TestCase;

/**
 * Pruning: abandoned enrolments, expired codes and used or replaced recovery
 * codes past the retention, and throttle rows whose window has ended, in
 * limited deletes that leave whatever still matters.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RecordPruner::class)]
#[CoversClass(PruneResult::class)]
#[CoversClass(PruneCommand::class)]
#[CoversClass(BoundedDelete::class)]
#[CoversClass(AttemptStore::class)]
#[CoversClass(EventDispatcher::class)]
#[CoversClass(MfaManager::class)]
final class PruningTest extends TestCase
{
    use ArrangesLifecycle;

    /** @var int The days of retention the tests configure. */
    private const int RETENTION = 30;

    /**
     * Arrange the application.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->arrangeLifecycle();

        config()->set('mfa.lifecycle.prune_after_days', self::RETENTION);
    }

    /**
     * An enrolment past the retention goes with its pending factor, and is
     * reported as expired with only what its row says; one within the retention
     * stays.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnAbandonedEnrollmentGoesWithItsFactor(): void
    {
        $signedIn = $this->signedInPerson();

        /** @var \Tests\Fixtures\Identities\TestUser $owner */
        $owner = TestUser::query()->create(['email' => 'owner@example.test']);

        [$old, $oldEnrollment]       = $this->pendingEnrollmentOf($owner, $this->daysAgo(self::RETENTION + 1));
        [$recent, $recentEnrollment] = $this->pendingEnrollmentOf($signedIn, $this->daysAgo(self::RETENTION - 1));

        $result = Mfa::prune();

        self::assertSame(1, $result->enrollments);
        self::assertFalse($this->isStored($old));
        self::assertFalse($this->isEnrollmentStored($oldEnrollment));
        self::assertTrue($this->isStored($recent));
        self::assertTrue($this->isEnrollmentStored($recentEnrollment));

        self::assertSame(['EnrollmentExpired'], $this->reportedNames());

        $event = $this->reported[0];

        self::assertInstanceOf(EnrollmentExpired::class, $event);
        self::assertSame($old->id, $event->factor->id);

        $context = $event->context();

        self::assertSame($owner->getMorphClass(), $context['identity_type']);
        self::assertSame((string) $owner->id, $context['identity_id']);
        self::assertSame(self::APPLICATION, $context['application']);
        self::assertNull($context['session_id']);
        self::assertNull($context['tenant_id']);
        self::assertNull($context['ip']);
    }

    /**
     * The expiry itself is exactly the retention's edge: an enrolment that
     * expired exactly then stays until the next run.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheRetentionsEdgeStays(): void
    {
        $user = $this->signedInPerson();

        [$factor] = $this->pendingEnrollmentOf($user, $this->daysAgo(self::RETENTION));

        self::assertSame(0, Mfa::prune()->enrollments);
        self::assertTrue($this->isStored($factor));
    }

    /**
     * An enrolment whose factor was confirmed or is gone goes on its own: a
     * confirmed factor is never touched, and nothing is reported as expired.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnEnrollmentWithoutAPendingFactorGoesAlone(): void
    {
        $user = $this->signedInPerson();

        [$confirmed, $ofConfirmed] = $this->pendingEnrollmentOf($user, $this->daysAgo(self::RETENTION + 1));
        [$gone, $ofGone]           = $this->pendingEnrollmentOf($user, $this->daysAgo(self::RETENTION + 2));

        $confirmed->update(['status' => 'confirmed']);
        $gone->delete();

        self::assertSame(2, Mfa::prune()->enrollments);
        self::assertTrue($this->isStored($confirmed));
        self::assertFalse($this->isEnrollmentStored($ofConfirmed));
        self::assertFalse($this->isEnrollmentStored($ofGone));
        self::assertSame([], $this->reportedNames());
    }

    /**
     * What was read before the lock is read again under it: an enrolment
     * confirmed or removed meanwhile, or no longer past the retention, is not
     * pruned on the old reading.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheEnrollmentIsReadAgainUnderTheLock(): void
    {
        $user = $this->signedInPerson();

        [$factor, $moved] = $this->pendingEnrollmentOf($user, $this->daysAgo(self::RETENTION + 2));
        [, $removed]      = $this->pendingEnrollmentOf($user, $this->daysAgo(self::RETENTION + 2));

        $raced = false;

        Enrollment::retrieved(function () use ($moved, $removed, &$raced): void {

            if ($raced) {
                return;
            }

            $raced = true;

            DB::table('mfa_enrollments')->where('id', $moved->id)->update(['expires_at' => CarbonImmutable::now()->addHour()]);
            DB::table('mfa_enrollments')->where('id', $removed->id)->delete();
        });

        try {
            self::assertSame(0, Mfa::prune()->enrollments);
        } finally {
            Enrollment::flushEventListeners();
        }

        self::assertTrue($this->isStored($factor));
        self::assertTrue($this->isEnrollmentStored($moved));
        self::assertSame([], $this->reportedNames());
    }

    /**
     * A model event that cancels a discard rolls that enrolment back and
     * propagates.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACancelledDeletionPropagates(): void
    {
        $user = $this->signedInPerson();

        [$factor, $enrollment] = $this->pendingEnrollmentOf($user, $this->daysAgo(self::RETENTION + 1));

        Enrollment::deleting(static fn (): bool => false);

        try {
            Mfa::prune();
            self::fail('A cancelled deletion was expected to throw.');
        } catch (WriteCancelledException $exception) {
            self::assertStringContainsString('cancelled the enrolment\'s deletion', $exception->getMessage());
        } finally {
            Enrollment::flushEventListeners();
        }

        self::assertTrue($this->isStored($factor));
        self::assertTrue($this->isEnrollmentStored($enrollment));
        self::assertSame([], $this->reportedNames());
    }

    /**
     * A delivered code past the retention goes; one within it stays, the send
     * caps reading it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testExpiredCodesGoPastTheRetention(): void
    {
        $user = $this->signedInPerson();
        $old  = $this->codeOf($user, $this->daysAgo(self::RETENTION + 1));
        $edge = $this->codeOf($user, $this->daysAgo(self::RETENTION));
        $live = $this->codeOf($user, CarbonImmutable::now()->addMinutes(5));

        self::assertSame(1, Mfa::prune()->codes);
        self::assertFalse(Code::query()->whereKey($old->id)->exists());
        self::assertTrue(Code::query()->whereKey($edge->id)->exists());
        self::assertTrue(Code::query()->whereKey($live->id)->exists());
    }

    /**
     * A recovery code used or replaced past the retention goes; a usable one,
     * or one used within it, stays.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testUsedOrReplacedRecoveryCodesGoPastTheRetention(): void
    {
        $user = $this->signedInPerson();

        $this->confirmedFactor($user);
        $this->recoveryCodesOf($user);

        $ids = RecoveryCode::query()->pluck('id')->all();

        RecoveryCode::query()->whereKey($ids[0])->update(['used_at' => $this->daysAgo(self::RETENTION + 1)]);
        RecoveryCode::query()->whereKey($ids[1])->update(['replaced_at' => $this->daysAgo(self::RETENTION + 1)]);
        RecoveryCode::query()->whereKey($ids[2])->update(['used_at' => $this->daysAgo(self::RETENTION - 1)]);

        self::assertSame(2, Mfa::prune()->recoveryCodes);
        self::assertSame(8, RecoveryCode::query()->count());
        self::assertTrue(RecoveryCode::query()->whereKey($ids[2])->exists());
    }

    /**
     * A throttle row whose window has ended goes whatever the retention, at its
     * very edge included; one still counting stays.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testThrottleRowsGoWhenTheirWindowEnds(): void
    {
        $store = $this->container()->make(AttemptStore::class);
        $now   = CarbonImmutable::now()->getTimestamp();

        $store->hold('ended', AttemptScope::IP, 3, $now - 1);
        $store->hold('edge', AttemptScope::IP, 3, $now);
        $store->hold('counting', AttemptScope::IP, 3, $now + 1);

        self::assertSame(2, Mfa::prune()->attempts);
        self::assertSame([], $store->read(['ended', 'edge']));
        self::assertArrayHasKey('counting', $store->read(['counting']));
    }

    /**
     * The retention is read from the configuration on every run.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheRetentionComesFromTheConfiguration(): void
    {
        $user = $this->signedInPerson();
        $code = $this->codeOf($user, $this->daysAgo(5));

        self::assertSame(0, Mfa::prune()->codes);

        config()->set('mfa.lifecycle.prune_after_days', 4);

        self::assertSame(1, Mfa::prune()->codes);
        self::assertFalse(Code::query()->whereKey($code->id)->exists());
    }

    /**
     * A delete statement removes at most a thousand rows and is repeated until
     * nothing is left, each carrying the query's conditions.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testDeletesComeInLimitedStatements(): void
    {
        $now  = CarbonImmutable::now();
        $rows = [];

        for ($row = 0; $row < 1001; $row++) {
            $rows[] = ['key' => 'k' . $row, 'scope' => AttemptScope::IP->value, 'hits' => 1, 'window_ends_at' => $now->subHour()->format('Y-m-d H:i:s')];
        }

        foreach (array_chunk($rows, 200) as $chunk) {
            DB::table('mfa_attempts')->insert($chunk);
        }

        DB::table('mfa_attempts')->insert(['key' => 'stays', 'scope' => AttemptScope::IP->value, 'hits' => 1, 'window_ends_at' => $now->addHour()->format('Y-m-d H:i:s')]);

        $statements = [];

        DB::listen(static function (QueryExecuted $query) use (&$statements): void {
            $statements[] = $query->sql;
        });

        self::assertSame(1001, BoundedDelete::run(DB::table('mfa_attempts')->where('window_ends_at', '<', $now->format('Y-m-d H:i:s'))));
        self::assertCount(2, $statements);
        self::assertStringContainsString('limit 1000', $statements[0]);
        self::assertStringStartsWith('delete', strtolower($statements[1]));
        self::assertSame(1, DB::table('mfa_attempts')->count());
    }

    /**
     * The command is registered, prunes, and prints how many of each kind went.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheCommandPrintsTheCounts(): void
    {
        $user = $this->signedInPerson();

        $this->pendingEnrollmentOf($user, $this->daysAgo(self::RETENTION + 1));
        $this->codeOf($user, $this->daysAgo(self::RETENTION + 1));

        self::assertInstanceOf(PruneCommand::class, Artisan::all()['mfa:prune'] ?? null);

        $exit = $this->container()->make(Kernel::class)->call('mfa:prune');

        self::assertSame(0, $exit);

        $output = Artisan::output();

        self::assertStringContainsString('Enrolments: 1', $output);
        self::assertStringContainsString('Delivered codes: 1', $output);
        self::assertStringContainsString('Recovery codes: 0', $output);
        self::assertStringContainsString('Throttle rows: 0', $output);
    }

    /**
     * The pruner can be handed to the scheduler by its class name, which calls
     * it through the container.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testThePrunerIsSchedulerFriendly(): void
    {
        $user = $this->signedInPerson();
        $code = $this->codeOf($user, $this->daysAgo(self::RETENTION + 1));

        $result = $this->container()->call(RecordPruner::class);

        self::assertInstanceOf(PruneResult::class, $result);
        self::assertSame(1, $result->codes);
        self::assertFalse(Code::query()->whereKey($code->id)->exists());
    }

    /**
     * A time the given number of days ago.
     *
     * @param  int  $days
     * @return \Carbon\CarbonImmutable
     */
    private function daysAgo(int $days): CarbonImmutable
    {
        return CarbonImmutable::now()->subDays($days);
    }

    /**
     * A delivered code of a factor of the user's, expiring as given.
     *
     * @param  \Tests\Fixtures\Identities\TestUser  $user
     * @param  \Carbon\CarbonImmutable  $expiresAt
     * @return \SineMacula\Laravel\Mfa\Models\Code
     */
    private function codeOf(TestUser $user, CarbonImmutable $expiresAt): Code
    {
        /** @var \SineMacula\Laravel\Mfa\Models\Code */
        return Code::query()->create([
            'factor_id'            => $this->confirmedFactor($user)->id,
            'authenticatable_type' => $user->getMorphClass(),
            'authenticatable_id'   => (string) $user->id,
            'purpose'              => 'sign_in',
            'application'          => self::APPLICATION,
            'session_id'           => 'session',
            'destination_hash'     => 'destination',
            'code_hash'            => 'code',
            'attempts'             => 0,
            'sends'                => 1,
            'sent_at'              => $expiresAt->subMinutes(10),
            'sent_times'           => [],
            'expires_at'           => $expiresAt,
        ]);
    }
}
