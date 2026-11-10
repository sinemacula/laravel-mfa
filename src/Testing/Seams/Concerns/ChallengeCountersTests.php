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
 * answered again as a success, and does not challenge a disabled factor; and
 * its own admission and report calls refuse a call outside a transaction and a
 * binding of another identity, and keep an enrolment challenge apart.
 *
 * A test case proves its implementation by using this trait and implementing
 * the hooks; each check delegates to `ChallengeCountersContract`. The admission
 * and report hooks call the adapter under test directly, as the owner does, so
 * the checks prove the adapter's wiring rather than the package's counters.
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
     * The path's admission and report calls refuse a call outside a
     * transaction.
     *
     * @return void
     */
    public function testChallengeCountersNeedTheCallersTransaction(): void
    {
        ChallengeCountersContract::assertTheCountersNeedTheCallersTransaction(
            $this->countedFactor(),
            $this->countedBinding(),
            $this->challengeAdmission(),
            $this->challengeReport(),
        );
    }

    /**
     * The path admits the identity's own binding and refuses a binding of
     * another identity.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testChallengeCountersRefuseABindingOfAnotherIdentity(): void
    {
        ChallengeCountersContract::assertABindingOfAnotherIdentityIsRefused(
            $this->countedFactor(),
            $this->countedBinding(),
            $this->challengeAdmission(),
            $this->challengeReport(),
        );
    }

    /**
     * A challenge for enrolling is not one for signing in, or the reverse.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testChallengeCountersKeepAnEnrollmentChallengeApart(): void
    {
        ChallengeCountersContract::assertAnEnrollmentChallengeIsItsOwn(
            $this->countedFactor(),
            $this->pendingFactor(),
            $this->countedBinding(),
            $this->challengeAdmission(),
            $this->challengeReport(),
        );
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
     * A pending factor of the identity's, as stored, holding no enrolment.
     *
     * @return \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor
     */
    abstract protected function pendingFactor(): EloquentFactor&Model;

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

    /**
     * Ask the adapter under test whether it admits a challenge of the factor
     * under the binding, as the owner asks before it sends or checks a code.
     *
     * Call the adapter itself, with the binding as given: never inside a
     * transaction of the hook's own, and letting every exception through.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor  $factor
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @return bool
     */
    abstract protected function isChallengeAdmitted(MultiFactorAuthenticatable $identity, EloquentFactor&Model $factor, ProofBinding $binding): bool;

    /**
     * Report a challenge's outcome through the adapter under test, as the owner
     * reports once it has consumed the challenge.
     *
     * Call the adapter itself, with the binding as given: never inside a
     * transaction of the hook's own, and letting every exception through.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor  $factor
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @param  bool  $passed
     * @return void
     */
    abstract protected function reportChallenge(MultiFactorAuthenticatable $identity, EloquentFactor&Model $factor, ProofBinding $binding, bool $passed): void;

    /**
     * The admission hook, for the counted identity.
     *
     * @return \Closure(\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor, \SineMacula\Laravel\Mfa\Proofs\ProofBinding): bool
     */
    private function challengeAdmission(): \Closure
    {
        $identity = $this->countedIdentity();

        return fn (EloquentFactor&Model $factor, ProofBinding $binding): bool => $this->isChallengeAdmitted($identity, $factor, $binding);
    }

    /**
     * The report hook, for the counted identity.
     *
     * @return \Closure(\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor, \SineMacula\Laravel\Mfa\Proofs\ProofBinding, bool): void
     */
    private function challengeReport(): \Closure
    {
        $identity = $this->countedIdentity();

        return function (EloquentFactor&Model $factor, ProofBinding $binding, bool $passed) use ($identity): void {
            $this->reportChallenge($identity, $factor, $binding, $passed);
        };
    }
}
