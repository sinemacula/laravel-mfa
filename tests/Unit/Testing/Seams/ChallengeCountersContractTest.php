<?php

declare(strict_types = 1);

namespace Tests\Unit\Testing\Seams;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\AssertionFailedError;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Attempts\ChallengeCounters;
use SineMacula\Laravel\Mfa\Codes\PackageChallengeGateway;
use SineMacula\Laravel\Mfa\Contracts\ChallengeGateway;
use SineMacula\Laravel\Mfa\Contracts\EloquentFactor;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Database\StorageConnection;
use SineMacula\Laravel\Mfa\Database\WriteConnection;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
use SineMacula\Laravel\Mfa\Testing\FakeEmailSender;
use SineMacula\Laravel\Mfa\Testing\Seams\ChallengeCountersContract;
use SineMacula\Laravel\Mfa\Testing\Seams\Concerns\ChallengeCountersTests;
use Tests\Fixtures\Codes\Concerns\ArrangesEmailChallenges;
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
