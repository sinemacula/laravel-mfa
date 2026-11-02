<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Testing\Seams\Concerns;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Mfa\Contracts\EloquentFactor;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
use SineMacula\Laravel\Mfa\Testing\Seams\ChallengeCountersContract;

/**
 * The challenge counters wiring kit: a challenge owner's path counts a failed
 * challenge against the factor inside the caller's transaction, before it
 * commits, counts nothing when that rolls back, nested or not, stops counting
 * once the identity's limit locks it, never counts a consumed challenge
 * answered again as a success, and does not challenge a disabled factor; the
 * counters refuse a call outside a transaction and a binding of another
 * identity.
 *
 * A test case proves its implementation by using this trait and implementing
 * the hooks; each check delegates to `ChallengeCountersContract`.
 *
 * @phpstan-require-extends \PHPUnit\Framework\TestCase
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
trait ChallengeCountersTests
{
    /**
     * A failed challenge is counted against its factor.
     *
     * @return void
     */
    public function testChallengeCountersCountAFailedChallenge(): void
    {
        ChallengeCountersContract::assertAFailedChallengeIsCounted($this->countedFactor(), $this->failChallenge(...));
    }

    /**
     * A failed challenge whose change rolls back counts nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testChallengeCountersCountNothingWhenRolledBack(): void
    {
        ChallengeCountersContract::assertARolledBackChallengeCountsNothing($this->countedFactor(), $this->failChallenge(...));
    }

    /**
     * A failed challenge is counted before the caller's transaction commits.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testChallengeCountersCountBeforeTheCallerCommits(): void
    {
        ChallengeCountersContract::assertAFailureIsCountedBeforeTheCallerCommits($this->countedFactor(), $this->failChallenge(...));
    }

    /**
     * A failed challenge whose nested transaction rolls back counts nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testChallengeCountersCountNothingWhenANestedTransactionRollsBack(): void
    {
        ChallengeCountersContract::assertANestedRollbackCountsNothing($this->countedFactor(), $this->failChallenge(...));
    }

    /**
     * The identity's limit locks it, and a further failure counts nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testChallengeCountersLockTheIdentityAtItsLimit(): void
    {
        ChallengeCountersContract::assertTheIdentityLimitLocksTheIdentity($this->countedIdentity(), $this->countedFactor(), $this->countedBinding(), $this->failChallenge(...));
    }

    /**
     * A consumed challenge answered again is never a success.
     *
     * @return void
     */
    public function testChallengeCountersNeverCountAReplayAsASuccess(): void
    {
        ChallengeCountersContract::assertAConsumedChallengeIsNeverASuccessAgain($this->countedFactor(), $this->consumeChallenge(...), $this->failChallenge(...));
    }

    /**
     * A disabled factor is not challenged.
     *
     * @return void
     */
    public function testChallengeCountersDoNotChallengeADisabledFactor(): void
    {
        ChallengeCountersContract::assertADisabledFactorIsNotChallenged($this->countedFactor(), $this->failChallenge(...));
    }

    /**
     * The counters refuse a call outside a transaction.
     *
     * @return void
     */
    public function testChallengeCountersNeedTheCallersTransaction(): void
    {
        ChallengeCountersContract::assertTheCountersNeedTheCallersTransaction($this->countedIdentity(), $this->countedFactor(), $this->countedBinding());
    }

    /**
     * The counters refuse a binding of another identity.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testChallengeCountersRefuseABindingOfAnotherIdentity(): void
    {
        ChallengeCountersContract::assertABindingOfAnotherIdentityIsRefused($this->countedIdentity(), $this->countedFactor(), $this->countedBinding());
    }

    /**
     * The identity whose challenges are counted.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable
     */
    abstract protected function countedIdentity(): MultiFactorAuthenticatable;

    /**
     * The identity's confirmed delivered factor, as stored.
     *
     * @return \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor
     */
    abstract protected function countedFactor(): EloquentFactor&Model;

    /**
     * What the identity's challenges are bound to.
     *
     * @return \SineMacula\Laravel\Mfa\Proofs\ProofBinding
     */
    abstract protected function countedBinding(): ProofBinding;

    /**
     * Fail one challenge of the factor through the owner's own path, as a
     * person submitting a wrong code would.
     *
     * @return void
     */
    abstract protected function failChallenge(): void;

    /**
     * Answer one challenge of the factor rightly through the owner's own path,
     * consuming it, and return what answers that same challenge again, with the
     * same code.
     *
     * @return \Closure(): void
     */
    abstract protected function consumeChallenge(): \Closure;
}
