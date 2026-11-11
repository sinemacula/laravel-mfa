<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Testing\Seams\Concerns;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Mfa\Contracts\EloquentFactor;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
use SineMacula\Laravel\Mfa\Testing\Seams\ChallengeCountersContract;

/**
 * The challenge counters wiring kit for a challenge owner's path. The admission
 * and report hooks call the adapter directly, so the checks prove its wiring
 * rather than the package's counters.
 *
 * @phpstan-require-extends \PHPUnit\Framework\TestCase
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
trait ChallengeCountersTests // phpcs:ignore SineMacula.Metrics.MaxMethodCount.TooManyMethods
{
    /**
     * @return void
     */
    public function testChallengeCountersCountAFailedChallenge(): void
    {
        ChallengeCountersContract::assertAFailedChallengeIsCounted($this->countedFactor(), $this->failChallenge(...));
    }

    /**
     * @return void
     *
     * @throws \Throwable
     */
    public function testChallengeCountersCountNothingWhenRolledBack(): void
    {
        ChallengeCountersContract::assertARolledBackChallengeCountsNothing($this->countedFactor(), $this->failChallenge(...));
    }

    /**
     * @return void
     *
     * @throws \Throwable
     */
    public function testChallengeCountersCountBeforeTheCallerCommits(): void
    {
        ChallengeCountersContract::assertAFailureIsCountedBeforeTheCallerCommits($this->countedFactor(), $this->failChallenge(...));
    }

    /**
     * @return void
     *
     * @throws \Throwable
     */
    public function testChallengeCountersCountNothingWhenANestedTransactionRollsBack(): void
    {
        ChallengeCountersContract::assertANestedRollbackCountsNothing($this->countedFactor(), $this->failChallenge(...));
    }

    /**
     * @return void
     *
     * @throws \Throwable
     */
    public function testChallengeCountersLockTheIdentityAtItsLimit(): void
    {
        ChallengeCountersContract::assertTheIdentityLimitLocksTheIdentity($this->countedIdentity(), $this->countedFactor(), $this->countedBinding(), $this->failChallenge(...));
    }

    /**
     * @return void
     */
    public function testChallengeCountersNeverCountAReplayAsASuccess(): void
    {
        ChallengeCountersContract::assertAConsumedChallengeIsNeverASuccessAgain($this->countedFactor(), $this->consumeChallenge(...), $this->failChallenge(...));
    }

    /**
     * @return void
     */
    public function testChallengeCountersDoNotChallengeADisabledFactor(): void
    {
        ChallengeCountersContract::assertADisabledFactorIsNotChallenged($this->countedFactor(), $this->failChallenge(...));
    }

    /**
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
     * @return void
     *
     * @throws \Throwable
     */
    public function testChallengeCountersRefuseABindingOfAnotherIdentity(): void
    {
        ChallengeCountersContract::assertABindingOfAnotherIdentityIsRefused(
            $this->countedFactor(),
            $this->countedBinding(),
            $this->otherCountedIdentity(),
            $this->challengeAdmission(),
            $this->challengeReport(),
        );
    }

    /**
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
     * @return \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable
     */
    abstract protected function countedIdentity(): MultiFactorAuthenticatable;

    /**
     * Another identity of the same kind, which need hold no factor.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable
     */
    abstract protected function otherCountedIdentity(): MultiFactorAuthenticatable;

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
     * @return \SineMacula\Laravel\Mfa\Proofs\ProofBinding
     */
    abstract protected function countedBinding(): ProofBinding;

    /**
     * Fail one challenge through the owner's own path, as a wrong code would.
     *
     * @return void
     */
    abstract protected function failChallenge(): void;

    /**
     * Answer one challenge rightly through the owner's path, and return a
     * closure that answers it again with the same code.
     *
     * @return \Closure(): void
     */
    abstract protected function consumeChallenge(): \Closure;

    /**
     * Call the adapter itself with the binding as given, outside any
     * transaction of the hook's own, letting every exception through.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor  $factor
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @return bool
     */
    abstract protected function isChallengeAdmitted(MultiFactorAuthenticatable $identity, EloquentFactor&Model $factor, ProofBinding $binding): bool;

    /**
     * Call the adapter itself as `isChallengeAdmitted()` does. A refusal
     * answers `false` or throws `OperationRefusedException`; anything else is
     * an error.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor  $factor
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @param  bool  $passed
     * @return bool
     */
    abstract protected function isChallengeReported(MultiFactorAuthenticatable $identity, EloquentFactor&Model $factor, ProofBinding $binding, bool $passed): bool;

    /**
     * @return \Closure(\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor, \SineMacula\Laravel\Mfa\Proofs\ProofBinding): bool
     */
    private function challengeAdmission(): \Closure
    {
        $identity = $this->countedIdentity();

        return fn (EloquentFactor&Model $factor, ProofBinding $binding): bool => $this->isChallengeAdmitted($identity, $factor, $binding);
    }

    /**
     * @return \Closure(\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor, \SineMacula\Laravel\Mfa\Proofs\ProofBinding, bool): bool
     */
    private function challengeReport(): \Closure
    {
        $identity = $this->countedIdentity();

        return fn (EloquentFactor&Model $factor, ProofBinding $binding, bool $passed): bool => $this->isChallengeReported($identity, $factor, $binding, $passed);
    }
}
