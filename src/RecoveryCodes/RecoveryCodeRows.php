<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\RecoveryCodes;

use Carbon\CarbonImmutable;
use Carbon\CarbonInterface;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Grammar;
use Illuminate\Database\Query\Builder as QueryBuilder;
use Illuminate\Database\Query\JoinClause;
use SineMacula\Laravel\Mfa\Contracts\RecoveryCode;
use SineMacula\Laravel\Mfa\Database\BoundedDelete;
use SineMacula\Laravel\Mfa\Database\ConfiguredModels;
use SineMacula\Laravel\Mfa\Database\GrammarExpression;
use SineMacula\Laravel\Mfa\Database\WriteConnection;
use SineMacula\Laravel\Mfa\Exceptions\WriteCanceledException;
use SineMacula\Laravel\Mfa\Models\IdentityState;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;

/**
 * Recovery code and state row statements; writes run under the identity's lock,
 * which the caller holds, and a cancelled save throws so the change rolls back.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class RecoveryCodeRows
{
    /**
     * @param  \Illuminate\Contracts\Config\Repository  $config
     */
    public function __construct(

        /** Read on every call so a changed model applies. */
        private Repository $config,
    ) {}

    /**
     * One unlocked statement, so the count and generation are of the same set.
     *
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofOwner  $owner
     * @return \SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeStatus
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\InvalidModelException
     */
    public function status(ProofOwner $owner): RecoveryCodeStatus
    {
        $code  = $this->codeModel();
        $state = new IdentityState;

        [$typeColumn, $keyColumn] = self::ownerColumns($code);

        $codes      = $code->getTable();
        $generation = $state->qualifyColumn('recovery_codes_generation');
        $generated  = $state->qualifyColumn('recovery_codes_generated_at');
        $count      = new GrammarExpression(static fn (Grammar $grammar): string => "count({$grammar->wrap($codes . '.' . $code->getKeyName())}) as remaining");

        $row = WriteConnection::query($state->newQuery())
            ->leftJoin($codes, static function (JoinClause $join) use ($state, $code, $codes, $typeColumn, $keyColumn, $generation): void {
                $join->on($codes . '.' . $typeColumn, '=', $state->qualifyColumn('authenticatable_type'))
                    ->on($codes . '.' . $keyColumn, '=', $state->qualifyColumn('authenticatable_id'))
                    ->on($codes . '.' . $code->getGenerationName(), '=', $generation)
                    ->whereNull($codes . '.' . $code->getUsedAtName())
                    ->whereNull($codes . '.' . $code->getReplacedAtName());
            })
            ->where($state->qualifyColumn('authenticatable_type'), $owner->type)
            ->where($state->qualifyColumn('authenticatable_id'), $owner->key)
            ->groupBy($generation, $generated)
            ->select([$generation, $generated, $count])
            ->first();

        $remaining = $row?->getAttribute('remaining');
        $at        = $row?->recovery_codes_generated_at;

        return new RecoveryCodeStatus(
            is_numeric($remaining) ? (int) $remaining : 0,
            $row->recovery_codes_generation ?? 0,
            $at === null ? null : CarbonImmutable::instance($at),
        );
    }

    /**
     * Replace the set with the hashes under the next generation and return it.
     *
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofOwner  $owner
     * @param  list<string>  $hashes
     * @return int
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\InvalidModelException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\WriteCanceledException
     */
    public function replace(ProofOwner $owner, array $hashes): int
    {
        $now   = CarbonImmutable::now();
        $state = $this->lockedState($owner);
        $model = $this->codeModel();

        $generation = $state->recovery_codes_generation + 1;

        $this->owned($model, $owner)
            ->whereNull($model->getReplacedAtName())
            ->update([$model->getReplacedAtName() => $now]);

        [$typeColumn, $keyColumn] = self::ownerColumns($model);

        foreach ($hashes as $hash) {
            $code = $model->newInstance();

            $code->setAttribute($typeColumn, $owner->type);
            $code->setAttribute($keyColumn, $owner->key);
            $code->setAttribute($model->getGenerationName(), $generation);
            $code->setAttribute($model->getCodeHashName(), $hash);
            self::save($code);
        }

        $state->recovery_codes_generation   = $generation;
        $state->recovery_codes_generated_at = $now;
        self::save($state);

        return $generation;
    }

    /**
     * Locking read, so a code used in the meantime is seen as used.
     *
     * @formatter:off
     *
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofOwner  $owner
     * @return \Illuminate\Database\Eloquent\Collection<int, \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\RecoveryCode>
     *
     * @formatter:on
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\InvalidModelException
     */
    public function usable(ProofOwner $owner): Collection
    {
        $model      = $this->codeModel();
        $generation = $this->lockedState($owner)->recovery_codes_generation;

        return $this->owned($model, $owner)
            ->where($model->getGenerationName(), $generation)
            ->whereNull($model->getUsedAtName())
            ->whereNull($model->getReplacedAtName())
            ->lockForUpdate()
            ->get();
    }

    /**
     * Whether this call marked the code used; false when already used or
     * replaced.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\RecoveryCode  $code
     * @return bool
     *
     * @imperative
     */
    public function markUsed(Model&RecoveryCode $code): bool
    {
        return WriteConnection::query($code->newQuery())
            ->whereKey($code->getKey())
            ->whereNull($code->getUsedAtName())
            ->whereNull($code->getReplacedAtName())
            ->update([$code->getUsedAtName() => CarbonImmutable::now()]) === 1;
    }

    /**
     * Delete the owner's codes and return whether it had a set.
     *
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofOwner  $owner
     * @return bool
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\InvalidModelException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\WriteCanceledException
     *
     * @imperative
     */
    public function delete(ProofOwner $owner): bool
    {
        $state   = $this->lockedState($owner);
        $deleted = $this->owned($this->codeModel(), $owner)->toBase()->delete();
        $existed = $state->recovery_codes_generated_at !== null || $deleted > 0;

        if ($state->recovery_codes_generated_at !== null) {
            $state->recovery_codes_generated_at = null;
            self::save($state);
        }

        return $existed;
    }

    /**
     * Delete codes used or replaced before the time in bounded mass deletes, so
     * no model event fires.
     *
     * @param  \Carbon\CarbonInterface  $before
     * @return int
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\InvalidModelException
     *
     * @imperative
     */
    public function prune(CarbonInterface $before): int
    {
        $code = $this->codeModel();

        return BoundedDelete::run($code->newQuery()
            ->toBase()
            ->where(static function (QueryBuilder $query) use ($code, $before): void {
                $query->where($code->getUsedAtName(), '<', $before)
                    ->orWhere($code->getReplacedAtName(), '<', $before);
            }));
    }

    /**
     * The caller's factor state lock has already created the row.
     *
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofOwner  $owner
     * @return \SineMacula\Laravel\Mfa\Models\IdentityState
     *
     * @throws \Illuminate\Database\Eloquent\ModelNotFoundException
     */
    private function lockedState(ProofOwner $owner): IdentityState
    {
        return IdentityState::query()
            ->where('authenticatable_type', $owner->type)
            ->where('authenticatable_id', $owner->key)
            ->lockForUpdate()
            ->firstOrFail();
    }

    /**
     * @formatter:off
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\RecoveryCode  $model
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofOwner  $owner
     * @return \Illuminate\Database\Eloquent\Builder<\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\RecoveryCode>
     *
     * @formatter:on
     */
    private function owned(Model&RecoveryCode $model, ProofOwner $owner): Builder
    {
        [$typeColumn, $keyColumn] = self::ownerColumns($model);

        return WriteConnection::query($model->newQuery())
            ->where($typeColumn, $owner->type)
            ->where($keyColumn, $owner->key);
    }

    /**
     * Read from the `authenticatable` relation, which an application's model
     * may name differently.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\RecoveryCode  $model
     * @return array{0: string, 1: string}
     */
    private static function ownerColumns(Model&RecoveryCode $model): array
    {
        $relation = $model->authenticatable();

        return [$relation->getMorphType(), $relation->getForeignKeyName()];
    }

    /**
     * @return \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\RecoveryCode
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\InvalidModelException
     */
    private function codeModel(): Model&RecoveryCode
    {
        $model = ConfiguredModels::recoveryCode($this->config);

        return new $model;
    }

    /**
     * Throw on a cancelled save so the change rolls back rather than commit
     * without it.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $model
     * @return void
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\WriteCanceledException
     */
    private static function save(Model $model): void
    {
        if (!$model->save()) {
            throw new WriteCanceledException(sprintf('A model event cancelled the save of a [%s], so the change it is part of was rolled back.', $model::class));
        }
    }
}
