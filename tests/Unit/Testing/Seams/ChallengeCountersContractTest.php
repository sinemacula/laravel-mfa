<?php

declare(strict_types = 1);

namespace Tests\Unit\Testing\Seams;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\AssertionFailedError;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Attempts\ChallengeCounters;
use SineMacula\Laravel\Mfa\Attempts\LockedFactors;
use SineMacula\Laravel\Mfa\Codes\PackageChallengeGateway;
use SineMacula\Laravel\Mfa\Contracts\ChallengeGateway;
use SineMacula\Laravel\Mfa\Contracts\EloquentFactor;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Database\StorageConnection;
use SineMacula\Laravel\Mfa\Database\WriteConnection;
use SineMacula\Laravel\Mfa\Enrollment\PendingEnrollments;
use SineMacula\Laravel\Mfa\Enums\EnrollmentAuthorization;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Models\IdentityState;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;
use SineMacula\Laravel\Mfa\Testing\FakeEmailSender;
use SineMacula\Laravel\Mfa\Testing\Seams\ChallengeCountersContract;
use SineMacula\Laravel\Mfa\Testing\Seams\Concerns\ChallengeCountersTests;
use Tests\Fixtures\Codes\Concerns\ArrangesEmailChallenges;
use Tests\Fixtures\Identities\NonEloquentIdentity;
use Tests\Fixtures\Identities\TestUser;
use Tests\TestCase;

/**
 * The challenge counters wiring kit proves the package's own challenge gateway,
 * which counts every outcome inside its transaction, and rejects a challenge
 * path that counts nothing.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ChallengeCountersContract::class)]
#[CoversClass(ChallengeCounters::class)]
#[CoversClass(PackageChallengeGateway::class)]
final class ChallengeCountersContractTest extends TestCase
{
    use ArrangesEmailChallenges, ChallengeCountersTests;

    /** @var \Tests\Fixtures\Identities\TestUser The person challenged. */
    private TestUser $user;

    /** @var \SineMacula\Laravel\Mfa\Models\Factor The person's email factor. */
    private Factor $factor;

    /** @var \SineMacula\Laravel\Mfa\Testing\FakeEmailSender The codes sent. */
    private FakeEmailSender $mailbox;

    /** @var ?string The challenge failed answers are given to, once sent. */
    private ?string $challenge = null;

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

        [$this->user, $this->factor, $this->mailbox] = $this->arrangeEmailChallenges();
    }

    /**
     * The kit rejects a pending factor that holds a live enrolment as one with
     * none, as it would a gateway's admission of it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRejectsAFactorAnEnrollmentChallengeWouldAdmit(): void
    {
        $pending = $this->pendingFactor();
        $binding = $this->countedBinding();

        $this->enroll($pending, $binding);

        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage('A pending factor with no live enrolment must not be challenged.');

        ChallengeCountersContract::assertAnEnrollmentChallengeIsItsOwn($this->user, $this->factor, $pending, $binding);
    }

    /**
     * The kit rejects a factor given as confirmed that an enrolment challenge
     * would admit, even when the pending factor given is refused.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRejectsAConfirmedFactorAnEnrollmentChallengeWouldAdmit(): void
    {
        $admitted = $this->pendingFactor();
        $binding  = $this->countedBinding();

        $this->enroll($admitted, $binding);

        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage('A confirmed factor must not be challenged for enrolling.');

        ChallengeCountersContract::assertAnEnrollmentChallengeIsItsOwn($this->user, $admitted, $this->pendingFactor(), $binding);
    }

    /**
     * The kit rejects an enrolment challenge that changes the factor's count,
     * though not the identity's.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRejectsAnEnrollmentChallengeThatChargesTheFactor(): void
    {
        $pending = $this->pendingFactor();
        $factor  = $this->factor;

        Factor::retrieved(static function (Factor $retrieved) use ($factor): void {
            if ($retrieved->getKey() !== $factor->getKey()) {
                return;
            }

            WriteConnection::query($factor->newQuery())->whereKey($factor->getKey())->increment($factor->getConsecutiveFailuresName());
        });

        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage('An enrolment challenge\'s outcome must change no factor\'s count.');

        ChallengeCountersContract::assertAnEnrollmentChallengeIsItsOwn($this->user, $this->factor, $pending, $this->countedBinding());
    }

    /**
     * The kit rejects an enrolment challenge that changes the identity's count.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRejectsAnEnrollmentChallengeThatChargesTheIdentity(): void
    {
        $pending = $this->pendingFactor();
        $binding = $this->countedBinding();

        Factor::retrieved(static function () use ($binding): void {
            IdentityState::query()
                ->where('authenticatable_type', $binding->identityType)
                ->where('authenticatable_id', $binding->identityKey)
                ->update(['consecutive_failures' => 1]);
        });

        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage('An enrolment challenge\'s outcome must change no identity\'s count.');

        ChallengeCountersContract::assertAnEnrollmentChallengeIsItsOwn($this->user, $this->factor, $pending, $binding);
    }

    /**
     * The kit rejects a challenge path that counts nothing.
     *
     * @return void
     */
    public function testRejectsAPathThatCountsNothing(): void
    {
        $this->expectException(AssertionFailedError::class);

        ChallengeCountersContract::assertAFailedChallengeIsCounted($this->factor, static function (): void {
            // A path that checks its own code and never reports the outcome.
        });
    }

    /**
     * The kit rejects a challenge path that counts in a transaction of its own,
     * committed whatever becomes of the change the challenge is part of.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRejectsAPathThatCommitsItsCountEarly(): void
    {
        $this->expectException(AssertionFailedError::class);

        ChallengeCountersContract::assertARolledBackChallengeCountsNothing($this->factor, function (): void {
            $this->countAFailure();
            DB::connection(StorageConnection::name())->commit();
        });
    }

    /**
     * A challenge path that fails leaves the kit's change rolled back, and its
     * failure propagates.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFailingPathIsRolledBack(): void
    {
        $connection = DB::connection(StorageConnection::name());
        $level      = $connection->transactionLevel();
        $failure    = new \LogicException('The challenge path failed.');

        try {
            ChallengeCountersContract::assertARolledBackChallengeCountsNothing($this->factor, static function () use ($failure): void {
                throw $failure;
            });
            self::fail('The path\'s failure was expected to propagate.');
        } catch (\LogicException $exception) {
            self::assertSame($failure, $exception);
        }

        self::assertSame($level, $connection->transactionLevel());
    }

    /**
     * The kit rejects a challenge path that challenges a disabled factor.
     *
     * @return void
     */
    public function testRejectsAPathThatChallengesADisabledFactor(): void
    {
        $this->expectException(AssertionFailedError::class);

        ChallengeCountersContract::assertADisabledFactorIsNotChallenged($this->factor, $this->countAFailure(...));
    }

    /**
     * The kit rejects counters that admit and report with no transaction of the
     * caller's to join, shown by calling them inside one.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRejectsCountersThatNeedNoTransaction(): void
    {
        $connection = DB::connection(StorageConnection::name());

        $connection->beginTransaction();

        $this->expectException(AssertionFailedError::class);

        try {
            ChallengeCountersContract::assertTheCountersNeedTheCallersTransaction($this->user, $this->factor, $this->emailBinding($this->user));
        } finally {
            $connection->rollBack();
        }
    }

    /**
     * The kit rejects a challenge path that counts only once the caller's
     * transaction commits, and leaves that transaction rolled back.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRejectsAPathThatCountsAfterTheCallerCommits(): void
    {
        self::rejects(fn () => ChallengeCountersContract::assertAFailureIsCountedBeforeTheCallerCommits($this->factor, function (): void {
            DB::connection(StorageConnection::name())->afterCommit($this->countAFailure(...));
        }));

        self::assertSame(0, DB::connection(StorageConnection::name())->transactionLevel());
        self::assertSame(0, $this->storedFailures());
    }

    /**
     * The kit rejects a challenge path that commits the caller's transaction to
     * count in it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRejectsAPathThatCommitsTheCallersTransaction(): void
    {
        self::rejects(fn () => ChallengeCountersContract::assertAFailureIsCountedBeforeTheCallerCommits($this->factor, function (): void {
            $this->countAFailure();
            DB::connection(StorageConnection::name())->commit();
        }));

        self::assertSame(0, DB::connection(StorageConnection::name())->transactionLevel());
    }

    /**
     * The kit rejects a challenge path that ends the caller's nested
     * transaction early to count in the outer one, and rolls both back.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRejectsAPathThatEscapesANestedTransaction(): void
    {
        self::rejects(fn () => ChallengeCountersContract::assertANestedRollbackCountsNothing($this->factor, function (): void {
            DB::connection(StorageConnection::name())->commit();
            $this->countAFailure();
        }));

        self::assertSame(0, DB::connection(StorageConnection::name())->transactionLevel());
        self::assertSame(0, $this->storedFailures());
    }

    /**
     * The kit rejects a challenge path that swaps the caller's nested
     * transaction for one of its own, so its count lands in the outer one.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRejectsAPathThatSwapsANestedTransaction(): void
    {
        self::rejects(fn () => ChallengeCountersContract::assertANestedRollbackCountsNothing($this->factor, function (): void {
            $connection = DB::connection(StorageConnection::name());

            $connection->commit();
            $this->countAFailure();
            $connection->beginTransaction();
        }));

        self::assertSame(0, DB::connection(StorageConnection::name())->transactionLevel());
    }

    /**
     * The kit rejects a challenge path that counts nothing, so the identity is
     * never locked, and puts the limits back.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRejectsAPathThatNeverLocksTheIdentity(): void
    {
        $limits = config('mfa.attempts');

        $binding = $this->emailBinding($this->user);

        self::rejects(fn () => ChallengeCountersContract::assertTheIdentityLimitLocksTheIdentity($this->user, $this->factor, $binding, static function (): void {
            // A path that checks its own code and never reports the outcome.
        }));

        self::assertSame($limits, config('mfa.attempts'));
    }

    /**
     * The kit rejects a challenge path that locks the identity at once.
     *
     * @return void
     */
    public function testRejectsAPathThatLocksTheIdentityEarly(): void
    {
        self::rejects(fn () => ChallengeCountersContract::assertTheIdentityLimitLocksTheIdentity($this->user, $this->factor, $this->emailBinding($this->user), function (): void {
            $this->failChallenge();
            $this->failChallenge();
        }));
    }

    /**
     * The kit rejects a challenge path that goes on counting against the factor
     * once the identity is locked.
     *
     * @return void
     */
    public function testRejectsAPathThatCountsALockedIdentity(): void
    {
        self::rejects(fn () => ChallengeCountersContract::assertTheIdentityLimitLocksTheIdentity($this->user, $this->factor, $this->emailBinding($this->user), function (): void {
            $this->failChallenge();
            $this->countAFailure();
        }));
    }

    /**
     * The kit puts the attempt limits back after the lockout check.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheLockoutCheckPutsTheLimitsBack(): void
    {
        $limits = config('mfa.attempts');

        ChallengeCountersContract::assertTheIdentityLimitLocksTheIdentity($this->user, $this->factor, $this->emailBinding($this->user), $this->failChallenge(...));

        self::assertSame($limits, config('mfa.attempts'));
    }

    /**
     * The kit sets the factor's limit above the identity's for the lockout
     * check, so a host's limit on factors at or below it does not lock the
     * factor first, and puts the host's limit back after.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheLockoutCheckHoldsTheFactorsLimitAboveTheIdentitys(): void
    {
        config()->set('mfa.attempts.factor_limit', 1);

        ChallengeCountersContract::assertTheIdentityLimitLocksTheIdentity($this->user, $this->factor, $this->emailBinding($this->user), $this->failChallenge(...));

        self::assertSame(1, config('mfa.attempts.factor_limit'));
    }

    /**
     * The kit accepts healthy counters for an identity whose key is the suffix
     * it names another identity by: the binding it makes from that key must
     * still name another identity, not the identity itself, whose factor and
     * sign-in are admissible.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAcceptsHealthyCountersForAnIdentityKeyedLikeTheSuffix(): void
    {
        $identity = new NonEloquentIdentity('-other');
        $owner    = ProofOwner::of($identity);
        $factor   = Factor::query()->create([
            'authenticatable_type' => $owner->type,
            'authenticatable_id'   => $owner->key,
            'type'                 => 'email',
            'destination'          => 'suffixed@example.test',
            'status'               => 'confirmed',
            'confirmed_at'         => CarbonImmutable::now(),
            'application'          => self::CHALLENGE_APPLICATION,
        ]);
        $binding = new ProofBinding($owner->type, $owner->key, self::CHALLENGE_APPLICATION, self::CHALLENGE_SESSION, Purpose::SIGN_IN);

        $this->actingAs($identity);

        $this->container()->make(ProofStore::class)->begin($identity, self::CHALLENGE_APPLICATION, self::CHALLENGE_SESSION);

        self::assertTrue(
            DB::connection(StorageConnection::name())->transaction(fn (): bool => $this->counters()->isUsable($identity, $factor, $binding)->isAdmitted()),
            'The identity\'s own factor and sign-in were expected to be admissible.',
        );

        ChallengeCountersContract::assertABindingOfAnotherIdentityIsRefused($identity, $factor, $binding);
    }

    /**
     * The kit rejects a replay check of a factor it can read no count for, as
     * one that counts no failure.
     *
     * @return void
     */
    public function testRejectsAReplayCheckOfAFactorWithNoStoredCount(): void
    {
        $unstored = (new Factor)->forceFill(['id' => '01JUNSTOREDFACTOR000000000']);

        self::rejects(fn () => ChallengeCountersContract::assertAConsumedChallengeIsNeverASuccessAgain($unstored, static fn (): \Closure => static function (): void {
            // A replay that changes nothing.
        }, static function (): void {
            // A path that counts nothing.
        }));
    }

    /**
     * The kit rejects a challenge path that counts a consumed challenge
     * answered again as a success.
     *
     * @return void
     */
    public function testRejectsAPathThatPassesAReplay(): void
    {
        self::rejects(fn () => ChallengeCountersContract::assertAConsumedChallengeIsNeverASuccessAgain($this->factor, function (): \Closure {
            $this->consumeChallenge();

            return function (): void {
                DB::connection(StorageConnection::name())->transaction(fn () => $this->counters()->report($this->user, $this->factor, $this->emailBinding($this->user), true));
            };
        }, $this->failChallenge(...)));
    }

    /**
     * The kit rejects a replay check whose failing path counts nothing, since a
     * reset could not then be seen.
     *
     * @return void
     */
    public function testRejectsAReplayCheckThatCountsNoFailure(): void
    {
        self::rejects(fn () => ChallengeCountersContract::assertAConsumedChallengeIsNeverASuccessAgain($this->factor, $this->consumeChallenge(...), static function (): void {
            // A path that checks its own code and never reports the outcome.
        }));
    }

    /**
     * The person.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable
     */
    #[\Override]
    protected function countedIdentity(): MultiFactorAuthenticatable
    {
        return $this->user;
    }

    /**
     * The person's email factor.
     *
     * @return \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor
     */
    #[\Override]
    protected function countedFactor(): EloquentFactor&Model
    {
        return $this->factor;
    }

    /**
     * A pending factor of the person's, holding no enrolment.
     *
     * @return \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor
     */
    #[\Override]
    protected function pendingFactor(): EloquentFactor&Model
    {
        return Factor::query()->create([
            'authenticatable_type' => $this->user->getMorphClass(),
            'authenticatable_id'   => (string) $this->user->id,
            'type'                 => 'email',
            'destination'          => 'pending@example.test',
        ]);
    }

    /**
     * The person's sign-in binding.
     *
     * @return \SineMacula\Laravel\Mfa\Proofs\ProofBinding
     */
    #[\Override]
    protected function countedBinding(): ProofBinding
    {
        return $this->emailBinding($this->user);
    }

    /**
     * Send a code through the default gateway, once, and submit a wrong one to
     * its challenge.
     *
     * @return void
     *
     * @throws \Throwable
     */
    #[\Override]
    protected function failChallenge(): void
    {
        $gateway = $this->container()->make(ChallengeGateway::class);
        $binding = $this->emailBinding($this->user);

        $this->challenge ??= (string) $gateway->send($this->factor, $binding)->challengeId;

        $code = self::lastEmailedCode($this->mailbox);

        $gateway->verify($this->factor, $binding, $this->challenge, $code === '000000' ? '111111' : '000000');
    }

    /**
     * Send a code through the default gateway and answer it rightly; answering
     * it again submits the same code to the same challenge.
     *
     * @return \Closure(): void
     *
     * @throws \Throwable
     */
    #[\Override]
    protected function consumeChallenge(): \Closure
    {
        $gateway   = $this->container()->make(ChallengeGateway::class);
        $binding   = $this->emailBinding($this->user);
        $challenge = (string) $gateway->send($this->factor, $binding)->challengeId;
        $code      = self::lastEmailedCode($this->mailbox);

        self::assertTrue($gateway->verify($this->factor, $binding, $challenge, $code)->hasPassed());

        $factor = $this->factor;

        return static function () use ($gateway, $factor, $binding, $challenge, $code): void {
            $gateway->verify($factor, $binding, $challenge, $code);
        };
    }

    /**
     * The counters.
     *
     * @return \SineMacula\Laravel\Mfa\Attempts\ChallengeCounters
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function counters(): ChallengeCounters
    {
        return $this->container()->make(ChallengeCounters::class);
    }

    /**
     * The factor's failures in a row, as committed or as the open transaction
     * sees them.
     *
     * @return int
     */
    private function storedFailures(): int
    {
        $count = WriteConnection::query($this->factor->newQuery())->whereKey($this->factor->getKey())->value('consecutive_failures');

        return is_numeric($count) ? (int) $count : 0;
    }

    /**
     * Give the factor a live enrolment bound to the binding's sign-in, as an
     * enrolment challenge would admit.
     *
     * @param  \SineMacula\Laravel\Mfa\Models\Factor  $factor
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function enroll(Factor $factor, ProofBinding $binding): void
    {
        $this->container()->make(PendingEnrollments::class)->create(
            (string) LockedFactors::idOf($factor),
            hash('sha256', 'grant'),
            new ProofBinding($binding->identityType, $binding->identityKey, $binding->application, $binding->sessionId, Purpose::ENROLLMENT),
            0,
            EnrollmentAuthorization::STEP_UP,
            CarbonImmutable::now()->addHour(),
        );
    }

    /**
     * Run a check that must reject what it is given.
     *
     * @param  \Closure(): void  $check
     * @return void
     */
    private static function rejects(\Closure $check): void
    {
        try {
            $check();
        } catch (AssertionFailedError) {
            return;
        }

        self::fail('The kit was expected to reject the path.');
    }

    /**
     * Count a failure against the factor directly, as a path that checks no
     * admission would.
     *
     * @return void
     */
    private function countAFailure(): void
    {
        WriteConnection::query($this->factor->newQuery())->whereKey($this->factor->getKey())->increment($this->factor->getConsecutiveFailuresName());
    }
}
