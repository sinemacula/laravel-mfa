<?php

declare(strict_types = 1);

namespace Tests\Unit\Attempts;

use Carbon\CarbonImmutable;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Attempts\AttemptService;
use SineMacula\Laravel\Mfa\Attempts\ChallengeAdmission;
use SineMacula\Laravel\Mfa\Attempts\ChallengeCounters;
use SineMacula\Laravel\Mfa\Context\IdentityContractSubjectType;
use SineMacula\Laravel\Mfa\Contracts\SubjectTypeResolver;
use SineMacula\Laravel\Mfa\Database\TableNames;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Events\LockoutApplied;
use SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Models\IdentityState;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;
use Tests\Fixtures\Codes\Concerns\ArrangesEmailChallenges;
use Tests\Fixtures\Context\Callers;
use Tests\Fixtures\Factors\InMemoryFactor;
use Tests\Fixtures\Factors\RemappedOwnerFactor;
use Tests\Fixtures\Identities\NonEloquentIdentity;
use Tests\Fixtures\Identities\TestUser;
use Tests\TestCase;

/**
 * Tests for `ChallengeCounters`, the calls a challenge owner makes into this
 * package's counts inside its own transaction: what is admitted and why not,
 * and how an outcome is counted.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ChallengeCounters::class)]
#[CoversClass(AttemptService::class)]
final class ChallengeCountersTest extends TestCase
{
    use ArrangesEmailChallenges;

    /** @var \Tests\Fixtures\Identities\TestUser The person challenged. */
    private TestUser $user;

    /** @var \SineMacula\Laravel\Mfa\Models\Factor The person's email factor. */
    private Factor $factor;

    /**
     * Sign a person in with an email factor.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        [$this->user, $this->factor] = $this->arrangeEmailChallenges();

        // Build the manager while the configuration is whole, as the
        // application would at boot, so a test may change it afterwards.
        $this->container()->make('mfa');
    }

    /**
     * Both calls refuse outside a transaction.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testBothCallsNeedATransaction(): void
    {
        $binding = $this->emailBinding($this->user);

        foreach (
            [
                fn () => $this->counters()->isUsable(Callers::of($this->user, 'web'), $this->factor, $binding),
                fn () => $this->counters()->report(Callers::of($this->user, 'web'), $this->factor, $binding, false),
            ] as $call
        ) {
            try {
                $call();
                self::fail('A call outside a transaction was expected to be refused.');
            } catch (\LogicException $exception) {
                self::assertSame('A challenge is admitted and its outcome reported only inside the caller\'s transaction on the storage connection.', $exception->getMessage());
            }
        }
    }

    /**
     * A confirmed factor of an enabled type, accepted after the session's first
     * factor and not locked, is admitted.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAdmitsAUsableFactor(): void
    {
        self::assertTrue($this->admission()->isAdmitted());
    }

    /**
     * A factor that keeps no state of its own is looked up among the identity's
     * stored factors, and refused as not found when it is none of them.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFactorThatKeepsNoStateIsLookedUpAmongTheStoredOnes(): void
    {
        $factor    = new InMemoryFactor(type: 'email', destination: self::ADDRESS);
        $admission = DB::transaction(fn (): ChallengeAdmission => $this->counters()->isUsable(Callers::of($this->user, 'web'), $factor, $this->emailBinding($this->user)));

        self::assertSame(FailureReason::NOT_FOUND, $admission->reason);
    }

    /**
     * A stored factor of a model of its own is locked through that model, by
     * the owner columns it names, not through the configured one.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAStoredFactorIsLockedThroughItsOwnModel(): void
    {
        Schema::table(TableNames::of(TableNames::FACTORS), static function (Blueprint $blueprint): void {
            $blueprint->renameColumn('authenticatable_type', 'owner_type');
            $blueprint->renameColumn('authenticatable_id', 'owner_id');
        });

        $remapped = RemappedOwnerFactor::query()->findOrFail($this->factor->id);

        self::assertTrue($this->admission($remapped)->isAdmitted());
    }

    /**
     * What is refused, and why, before or under the lock.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRefusesWhatMayNotBeChallenged(): void
    {
        $owner = $this->emailBinding($this->user);
        $other = new ProofBinding($owner->identityType, 'someone-else', $owner->application, $owner->sessionId, Purpose::SIGN_IN);

        self::assertSame(FailureReason::NOT_FOUND, $this->admission(binding: $other)->reason);

        /** @var \Tests\Fixtures\Identities\TestUser $stranger */
        $stranger = TestUser::query()->create(['email' => 'stranger@example.test']);
        $theirs   = $this->factor->replicate();

        $theirs->setAttribute('authenticatable_id', ProofOwner::of($stranger)->key);
        $theirs->save();

        self::assertSame(FailureReason::NOT_FOUND, $this->admission(factor: $theirs)->reason);

        $this->factor->update(['status' => 'pending']);

        self::assertSame(FailureReason::NOT_CONFIRMED, $this->admission()->reason);

        $this->factor->update(['status' => 'confirmed']);

        config()->set('mfa.applications.web.types', ['totp']);

        self::assertSame(FailureReason::TYPE_NOT_ENABLED, $this->admission()->reason);

        config()->set('mfa.applications.web', ['types' => ['email']]);

        self::assertSame(FailureReason::NOT_ACCEPTED, $this->admission()->reason);
    }

    /**
     * A machine and an inactive identity are refused.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRefusesAMachineAndAnInactiveIdentity(): void
    {
        $resolver = \Mockery::mock(SubjectTypeResolver::class);
        $resolver->shouldReceive('isPerson')->andReturnFalse();

        $this->container()->instance(SubjectTypeResolver::class, $resolver);

        self::assertSame(FailureReason::MACHINE_IDENTITY, $this->admission()->reason);

        $this->container()->instance(SubjectTypeResolver::class, new IdentityContractSubjectType);

        $inactive = new NonEloquentIdentity('plain-1', active: false);
        $binding  = new ProofBinding(NonEloquentIdentity::class, 'plain-1', 'web', self::CHALLENGE_SESSION, Purpose::SIGN_IN);

        self::assertSame(FailureReason::IDENTITY_INACTIVE, DB::transaction(fn () => $this->counters()->isUsable(Callers::of($inactive, 'web'), $this->factor, $binding))->reason);
    }

    /**
     * A factor disabled at the failure ceiling and an identity locked out are
     * refused as locked, with when the lockout ends.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRefusesALockedFactorOrIdentity(): void
    {
        $this->factor->update(['disabled_at' => CarbonImmutable::now()]);

        $disabled = $this->admission();

        self::assertSame(FailureReason::LOCKED, $disabled->reason);
        self::assertNull($disabled->lockedUntil);

        $this->factor->update(['disabled_at' => null]);

        $until = CarbonImmutable::now()->addMinutes(10)->startOfSecond();

        IdentityState::query()->updateOrCreate(
            ['authenticatable_type' => TestUser::class, 'authenticatable_id' => ProofOwner::of($this->user)->key],
            ['locked_until' => $until],
        );

        $locked = $this->admission();

        self::assertSame(FailureReason::LOCKED, $locked->reason);
        self::assertSame($until->getTimestamp(), $locked->lockedUntil?->getTimestamp());
    }

    /**
     * A failure is counted against the factor and the identity, and a success
     * resets the factor's failures in a row.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testReportsAreCounted(): void
    {
        $binding = $this->emailBinding($this->user);

        $failed = DB::transaction(fn () => $this->counters()->report(Callers::of($this->user, 'web'), $this->factor, $binding, false));

        self::assertTrue($failed->isFailed());
        self::assertSame(1, $this->failures());
        self::assertSame(1, IdentityState::query()->sole()->consecutive_failures);

        $passed = DB::transaction(fn () => $this->counters()->report(Callers::of($this->user, 'web'), $this->factor, $binding, true));

        self::assertTrue($passed->passed);
        self::assertSame(0, $this->failures());
    }

    /**
     * An outcome reported in a change that rolls back counts nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARolledBackReportCountsNothing(): void
    {
        DB::beginTransaction();

        $this->counters()->report(Callers::of($this->user, 'web'), $this->factor, $this->emailBinding($this->user), false);

        DB::rollBack();

        self::assertSame(0, $this->failures());
    }

    /**
     * Competing failures cannot overrun the identity's cap: once it locks, a
     * further outcome is refused and counted nowhere, and the lockout is
     * reported once the change commits.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheIdentityCapIsNotOverrun(): void
    {
        config()->set('mfa.attempts.identity_limit', 2);

        Event::fake([LockoutApplied::class]);

        $binding  = $this->emailBinding($this->user);
        $outcomes = DB::transaction(fn () => [
            $this->counters()->report(Callers::of($this->user, 'web'), $this->factor, $binding, false),
            $this->counters()->report(Callers::of($this->user, 'web'), $this->factor, $binding, false),
            $this->counters()->report(Callers::of($this->user, 'web'), $this->factor, $binding, false),
        ]);

        self::assertTrue($outcomes[0]->isFailed());
        self::assertTrue($outcomes[1]->isFailed());
        self::assertTrue($outcomes[2]->isRefused());
        self::assertSame(2, $this->failures());
        self::assertFalse($this->admission()->isAdmitted());
        Event::assertDispatched(LockoutApplied::class);
    }

    /**
     * A report bound to another identity is refused.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAReportOfAnotherIdentityIsRefused(): void
    {
        $owner = $this->emailBinding($this->user);
        $other = new ProofBinding($owner->identityType, 'someone-else', $owner->application, $owner->sessionId, Purpose::SIGN_IN);

        $this->expectException(OperationRefusedException::class);

        DB::transaction(fn () => $this->counters()->report(Callers::of($this->user, 'web'), $this->factor, $other, false));
    }

    /**
     * Ask whether the factor may be challenged, in a transaction.
     *
     * @param  ?\SineMacula\Laravel\Mfa\Models\Factor  $factor
     * @param  ?\SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @return \SineMacula\Laravel\Mfa\Attempts\ChallengeAdmission
     *
     * @throws \Throwable
     */
    private function admission(?Factor $factor = null, ?ProofBinding $binding = null): ChallengeAdmission
    {
        $caller = Callers::of($this->user, 'web');

        return DB::transaction(fn (): ChallengeAdmission => $this->counters()->isUsable($caller, $factor ?? $this->factor, $binding ?? $this->emailBinding($this->user)));
    }

    /**
     * The factor's failures in a row, as stored.
     *
     * @return int
     */
    private function failures(): int
    {
        return Factor::query()->findOrFail($this->factor->id)->getConsecutiveFailures();
    }

    /**
     * The counters under test.
     *
     * @return \SineMacula\Laravel\Mfa\Attempts\ChallengeCounters
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function counters(): ChallengeCounters
    {
        return $this->container()->make(ChallengeCounters::class);
    }
}
