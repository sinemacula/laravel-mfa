<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Concerns;

use Illuminate\Container\Container;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Mfa\Database\ConfiguredModels;
use SineMacula\Laravel\Mfa\Database\WriteConnection;
use SineMacula\Laravel\Mfa\Enums\FactorStatus;
use SineMacula\Laravel\Mfa\Lifecycle\ForgetIdentity;
use SineMacula\Laravel\Mfa\Requirements\Requirement;
use SineMacula\Laravel\Mfa\Support\FactorOwnerColumns;

/**
 * Factor ownership for an Eloquent identity model beside
 * `MultiFactorAuthenticatable`, with defaults (a person, active, requiring
 * nothing) a model overrides. Hard-deleting the model forgets its MFA data.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @phpstan-require-extends \Illuminate\Database\Eloquent\Model
 */
trait HasFactors
{
    /**
     * Forgets the identity on `deleted`, so a cancelled or failed delete keeps
     * its factors and a soft delete forgets nothing. It joins an open
     * transaction on the storage connection.
     *
     * @return void
     */
    public static function bootHasFactors(): void
    {
        static::deleted(static function (Model $identity): void {

            if (!$identity instanceof Authenticatable || (method_exists($identity, 'isForceDeleting') && !$identity->isForceDeleting())) {
                return;
            }

            Container::getInstance()->make(ForgetIdentity::class)->forget($identity);
        });
    }

    /**
     * A person may; the default assumes one.
     *
     * @return bool
     */
    public function canHoldFactors(): bool
    {
        return true;
    }

    /**
     * The default assumes every identity the guard returns is active.
     *
     * @return bool
     */
    public function isMfaActive(): bool
    {
        return true;
    }

    /**
     * What the identity requires of its own sign-ins; none by default.
     *
     * @return ?\SineMacula\Laravel\Mfa\Requirements\Requirement
     */
    public function requiresAdditionalFactor(): ?Requirement
    {
        return null;
    }

    /**
     * Any status but exactly `pending` counts, compared in PHP because a SQL
     * collation may ignore case or padding, so a corrupt status fails closed.
     * Read on the write connection so a fresh change beats replica lag.
     *
     * @return bool
     */
    public function isMfaEnabled(): bool
    {
        $factors = $this->authFactors();
        $column  = $factors->getModel()->getStatusName();

        return WriteConnection::query($factors)
            ->toBase()
            ->pluck($column)
            ->contains(static fn (mixed $status): bool => $status !== FactorStatus::PENDING->value);
    }

    /**
     * Matched on the factor model's own `authenticatable` owner columns.
     *
     * @formatter:off
     *
     * @return \Illuminate\Database\Eloquent\Builder<\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor>
     *
     * @formatter:on
     */
    public function authFactors(): Builder
    {
        $model  = ConfiguredModels::factor(Container::getInstance()->make('config'));
        $factor = new $model;

        [$typeColumn, $keyColumn] = FactorOwnerColumns::of($factor);

        $key = $this instanceof Authenticatable ? $this->getAuthIdentifier() : $this->getKey();

        /** @var \Illuminate\Database\Eloquent\Builder<\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor> */
        return $factor->newQuery()
            ->where($factor->qualifyColumn($typeColumn), $this->getMorphClass())
            ->where($factor->qualifyColumn($keyColumn), is_int($key) ? (string) $key : $key);
    }
}
