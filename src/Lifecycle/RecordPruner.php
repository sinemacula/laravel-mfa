<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Lifecycle;

use Carbon\CarbonImmutable;
use Carbon\CarbonInterface;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Mfa\Attempts\AttemptStore;
use SineMacula\Laravel\Mfa\Attempts\LockedFactors;
use SineMacula\Laravel\Mfa\Contracts\EloquentFactor;
use SineMacula\Laravel\Mfa\Database\BoundedDelete;
use SineMacula\Laravel\Mfa\Database\ConfiguredModels;
use SineMacula\Laravel\Mfa\Database\WriteConnection;
use SineMacula\Laravel\Mfa\Enrollment\PendingEnrollments;
use SineMacula\Laravel\Mfa\Events\EnrollmentExpired;
use SineMacula\Laravel\Mfa\Events\EventDispatcher;
use SineMacula\Laravel\Mfa\Factors\FactorSummary;
use SineMacula\Laravel\Mfa\Models\Code;
use SineMacula\Laravel\Mfa\Models\Enrollment;
use SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeService;
use SineMacula\Laravel\Mfa\Support\FactorStateTransaction;

/**
 * Deletes expired records older than `mfa.lifecycle.prune_after_days`;
 * throttle rows go once their window ends. The one-day minimum retention
 * outlives the longest send window a delivered code counts towards.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class RecordPruner
{
    /**
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @param  \SineMacula\Laravel\Mfa\Enrollment\PendingEnrollments  $enrollments
     * @param  \SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeService  $recoveryCodes
     * @param  \SineMacula\Laravel\Mfa\Attempts\AttemptStore  $attempts
     * @param  \SineMacula\Laravel\Mfa\Events\EventDispatcher  $events
     */
    public function __construct(

        /** Read on every run so a changed retention applies. */
        private Repository $config,

        /** Enrolments in progress. */
        private PendingEnrollments $enrollments,

        /** Recovery codes. */
        private RecoveryCodeService $recoveryCodes,

        /** Throttle rows. */
        private AttemptStore $attempts,

        /** Dispatches the expiry events. */
        private EventDispatcher $events,
    ) {}

    /**
     * @return \SineMacula\Laravel\Mfa\Lifecycle\PruneResult
     *
     * @throws \InvalidArgumentException
     * @throws \Throwable
     */
    public function __invoke(): PruneResult
    {
        $now    = CarbonImmutable::now();
        $before = $now->subDays((new LifecycleSettings($this->config))->pruneAfterDays());

        return new PruneResult(
            enrollments: $this->pruneEnrollments($before),
            codes: BoundedDelete::run(Code::query()->toBase()->where('expires_at', '<', $before)),
            recoveryCodes: $this->recoveryCodes->prune($before),
            attempts: $this->attempts->prune($now->getTimestamp()),
        );
    }

    /**
     * Each enrolment goes on its own, under its owner's lock.
     *
     * @param  \Carbon\CarbonInterface  $before
     * @return int
     *
     * @throws \Throwable
     */
    private function pruneEnrollments(CarbonInterface $before): int
    {
        $pruned = 0;

        foreach (WriteConnection::query(Enrollment::query())->where('expires_at', '<', $before)->lazyById() as $enrollment) {
            $pruned += $this->pruneEnrollment($enrollment, $before) ? 1 : 0;
        }

        return $pruned;
    }

    /**
     * Read again under the lock, so one confirmed or restarted meanwhile stays.
     *
     * @param  \SineMacula\Laravel\Mfa\Models\Enrollment  $read
     * @param  \Carbon\CarbonInterface  $before
     * @return bool
     *
     * @throws \Throwable
     *
     * @imperative
     */
    private function pruneEnrollment(Enrollment $read, CarbonInterface $before): bool
    {
        $model = ConfiguredModels::factor($this->config);

        return FactorStateTransaction::forOwner(
            $read->authenticatable_type,
            $read->authenticatable_id,
            new $model,
            function (Collection $factors) use ($read, $before): bool {

                $enrollment = $this->enrollments->forFactor($read->factor_id);

                if ($enrollment === null || !$enrollment->expires_at->lessThan($before)) {
                    return false;
                }

                $factor = LockedFactors::withId($enrollment->factor_id, $factors);

                if ($factor === null || $factor->isConfirmed()) {

                    $this->enrollments->forget($enrollment);

                    return true;
                }

                $this->discard($enrollment, $factor);

                return true;
            },
        );
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Models\Enrollment  $enrollment
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor  $factor
     * @return void
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\WriteCanceledException
     */
    private function discard(Enrollment $enrollment, EloquentFactor&Model $factor): void
    {
        $summary = FactorSummary::fromFactor($factor);

        $this->enrollments->discard($enrollment, $factor);

        $this->events->dispatch(new EnrollmentExpired(
            $this->events->ownerContext($enrollment->authenticatable_type, $enrollment->authenticatable_id, $enrollment->application),
            $summary,
        ));
    }
}
