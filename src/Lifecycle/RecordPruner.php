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
 * Deletes what is no longer of use, older than
 * `mfa.lifecycle.prune_after_days`: enrolments past their expiry, with a factor
 * still pending, delivered codes past theirs, and recovery codes used or
 * replaced; and, with no retention, throttle rows whose window has ended, which
 * count nothing.
 *
 * `Mfa::prune()` runs it; the package schedules nothing itself. `mfa:prune` is
 * the same from the console.
 *
 * Delivered codes outlive the send window they count towards, whose longest is
 * a day, the shortest retention. Those, recovery codes and throttle rows go in
 * bounded statements (see `Database\BoundedDelete`), with no model event. An
 * enrolment goes on its own, under its owner's factor state lock, read again
 * there, so one confirmed or restarted meanwhile is left alone, and a model
 * event that cancels its deletion rolls back and propagates.
 * `EnrollmentExpired` reports each pending factor discarded, once its change
 * commits, with only what the stored row says in its context.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class RecordPruner
{
    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @param  \SineMacula\Laravel\Mfa\Enrollment\PendingEnrollments  $enrollments
     * @param  \SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeService  $recoveryCodes
     * @param  \SineMacula\Laravel\Mfa\Attempts\AttemptStore  $attempts
     * @param  \SineMacula\Laravel\Mfa\Events\EventDispatcher  $events
     */
    public function __construct(

        /** The configuration the retention and the factor model are read from. */
        private Repository $config,

        /** The enrolments in progress. */
        private PendingEnrollments $enrollments,

        /** The recovery codes. */
        private RecoveryCodeService $recoveryCodes,

        /** The throttle rows. */
        private AttemptStore $attempts,

        /** The dispatcher of the expiry events. */
        private EventDispatcher $events,
    ) {}

    /**
     * Prune, and say how many records of each kind went.
     *
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
     * Prune every enrolment past its expiry before the time, each on its own.
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
     * Under its owner's lock, read the enrolment again and delete it if it is
     * still past its expiry, with its factor if that is still pending. Returns
     * whether it went.
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
     * Delete the enrolment and its pending factor, and report it.
     *
     * @param  \SineMacula\Laravel\Mfa\Models\Enrollment  $enrollment
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor  $factor
     * @return void
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\WriteCancelledException
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
