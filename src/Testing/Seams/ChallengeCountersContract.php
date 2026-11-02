<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Testing\Seams;

use Carbon\CarbonImmutable;
use Illuminate\Container\Container;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Assert;
use SineMacula\Laravel\Mfa\Attempts\ChallengeCounters;
use SineMacula\Laravel\Mfa\Contracts\EloquentFactor;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Database\StorageConnection;
use SineMacula\Laravel\Mfa\Database\WriteConnection;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;

/**
 * What a challenge owner's wiring to `Attempts\ChallengeCounters` must
 * guarantee, as assertions: a failed challenge is counted against the factor,
 * inside the owner's transaction, so one that rolls back counts nothing; a
 * factor disabled at the failure ceiling is not challenged; and the counters
 * themselves refuse a call outside a transaction and a binding of another
 * identity.
 *
 * The closure given fails one challenge of the identity's factor through the
 * owner's own path, as a person submitting a wrong code would.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
final class ChallengeCountersContract
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * A failed challenge adds one to the factor's failures in a row.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor  $factor
     * @param  \Closure(): void  $failChallenge
     * @return void
     */
    public static function assertAFailedChallengeIsCounted(EloquentFactor&Model $factor, \Closure $failChallenge): void
    {
        $before = self::failures($factor);

        self::attempt($failChallenge);

        Assert::assertSame($before + 1, self::failures($factor), 'A failed challenge must be counted against its factor.');
    }

    /**
     * A failed challenge inside a change on the storage connection that rolls
     * back counts nothing.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor  $factor
     * @param  \Closure(): void  $failChallenge
     * @return void
     *
     * @throws \Throwable
     */
    public static function assertARolledBackChallengeCountsNothing(EloquentFactor&Model $factor, \Closure $failChallenge): void
    {
        $before     = self::failures($factor);
        $connection = DB::connection(StorageConnection::name());

        $connection->beginTransaction();

        try {
            self::attempt($failChallenge);
        } finally {
            $connection->rollBack();
        }

        Assert::assertSame($before, self::failures($factor), 'A challenge whose change rolls back must count nothing.');
    }

    /**
     * A factor disabled at the failure ceiling is not challenged, so a failed
     * attempt on it counts nothing more.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor  $factor
     * @param  \Closure(): void  $failChallenge
     * @return void
     */
    public static function assertADisabledFactorIsNotChallenged(EloquentFactor&Model $factor, \Closure $failChallenge): void
    {
        $factor->newQuery()->whereKey($factor->getKey())->update([$factor->getDisabledAtName() => CarbonImmutable::now()]);

        $before = self::failures($factor);

        self::attempt($failChallenge);

        Assert::assertSame($before, self::failures($factor), 'A disabled factor must not be challenged.');
    }

    /**
     * The counters refuse to admit or report outside a transaction on the
     * storage connection.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor  $factor
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @return void
     */
    public static function assertTheCountersNeedTheCallersTransaction(MultiFactorAuthenticatable $identity, EloquentFactor&Model $factor, ProofBinding $binding): void
    {
        $counters = self::counters();

        foreach ([static fn () => $counters->isUsable($identity, $factor, $binding), static fn () => $counters->report($identity, $factor, $binding, false)] as $call) {
            $outcome = null;

            try {
                $call();
            } catch (\Throwable $exception) {
                $outcome = $exception;
            }

            Assert::assertInstanceOf(\LogicException::class, $outcome, 'The counters must refuse a call made outside the caller\'s transaction.');
        }
    }

    /**
     * The counters refuse a binding that names another identity.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor  $factor
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @return void
     *
     * @throws \Throwable
     */
    public static function assertABindingOfAnotherIdentityIsRefused(MultiFactorAuthenticatable $identity, EloquentFactor&Model $factor, ProofBinding $binding): void
    {
        $other = new ProofBinding($binding->identityType, $binding->identityKey . '-other', $binding->application, $binding->sessionId, Purpose::SIGN_IN);

        DB::connection(StorageConnection::name())->transaction(static function () use ($identity, $factor, $other): void {
            Assert::assertSame(FailureReason::NOT_FOUND, self::counters()->isUsable($identity, $factor, $other)->reason, 'A binding of another identity must not be admitted.');
        });
    }

    /**
     * Fail one challenge through the owner's path; a refusal it throws is the
     * owner's way of saying no.
     *
     * @param  \Closure(): void  $failChallenge
     * @return void
     */
    private static function attempt(\Closure $failChallenge): void
    {
        try {
            $failChallenge();
        } catch (\RuntimeException) {
            // A refused challenge counts nothing; the count is read after.
        }
    }

    /**
     * The factor's failures in a row, as stored.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor  $factor
     * @return int
     */
    private static function failures(EloquentFactor&Model $factor): int
    {
        $count = WriteConnection::query($factor->newQuery())->whereKey($factor->getKey())->value($factor->getConsecutiveFailuresName());

        return is_numeric($count) ? (int) $count : 0;
    }

    /**
     * The counters, as the container builds them.
     *
     * @return \SineMacula\Laravel\Mfa\Attempts\ChallengeCounters
     */
    private static function counters(): ChallengeCounters
    {
        return Container::getInstance()->make(ChallengeCounters::class);
    }
}
