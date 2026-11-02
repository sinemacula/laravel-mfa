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
 * What an Eloquent identity model needs to hold factors, used with the
 * `MultiFactorAuthenticatable` contract: its factors, whether it has a
 * confirmed one, and the defaults of the questions every operation asks first
 * (a person, active, requiring nothing of its own), which the model overrides
 * where its own state answers them. Deleting the model, other than softly,
 * deletes everything the package holds for it (see `Lifecycle\ForgetIdentity`).
 *
 * The factors are those of the configured factor model, owned through the owner
 * columns of its `authenticatable` relation.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @phpstan-require-extends \Illuminate\Database\Eloquent\Model
 */
trait HasFactors
{
    /**
     * Delete everything the package holds for the identity once it is deleted:
     * its factors, enrolments, delivered codes, recovery codes, passkey
     * associations and factor state.
     *
     * It runs on the `deleted` event, after the identity's row is gone, so a
     * delete that another listener cancels, or that fails, leaves the
     * identity's factors in place rather than an identity without them. A soft
     * delete forgets nothing, so a restored identity still has its factors; a
     * force delete forgets it. The forgetting commits on its own unless the
     * delete runs inside a transaction on the storage connection, which it then
     * joins, so the two commit or roll back as one.
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
     * Determine whether the identity may hold factors: a person may, which the
     * default assumes.
     *
     * @return bool
     */
    public function canHoldFactors(): bool
    {
        return true;
    }

    /**
     * Determine whether the identity is active, which the default assumes of
     * every identity the guard returns.
     *
     * @return bool
     */
    public function isMfaActive(): bool
    {
        return true;
    }

    /**
     * The additional verification the identity requires of its own sign-ins;
     * none by default.
     *
     * @return ?\SineMacula\Laravel\Mfa\Requirements\Requirement
     */
    public function requiresAdditionalFactor(): ?Requirement
    {
        return null;
    }

    /**
     * Determine whether the identity has a factor that is not pending: a
     * confirmed one, or one whose stored status is none the package knows. Only
     * a status of exactly `pending` does not count, compared here rather than
     * in SQL, where a collation may ignore case or padding. A corrupt status so
     * holds the identity to MFA, and its factor throws when it is read, so the
     * person cannot pass until a reset rather than being let on as having no
     * factor. The factors are read from the write connection (see
     * `Database\WriteConnection`), so a factor just confirmed or removed is
     * seen before a replica catches up.
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
     * The identity's factors, of the configured factor model, found by the
     * owner columns of the model's `authenticatable` relation, which an
     * application's own model may name differently, holding the identity's type
     * (its morph class) and key (its auth identifier).
     *
     * @formatter:off
     *
     * @return \Illuminate\Database\Eloquent\Builder<\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\Factor>
     *
     * @formatter:on
     */
    public function authFactors(): Builder
    {
        $model  = ConfiguredModels::factor(Container::getInstance()->make('config'));
        $factor = new $model;

        [$typeColumn, $keyColumn] = FactorOwnerColumns::of($factor);

        $key = $this instanceof Authenticatable ? $this->getAuthIdentifier() : $this->getKey();

        /** @var \Illuminate\Database\Eloquent\Builder<\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\Factor> */
        return $factor->newQuery()
            ->where($factor->qualifyColumn($typeColumn), $this->getMorphClass())
            ->where($factor->qualifyColumn($keyColumn), is_int($key) ? (string) $key : $key);
    }
}
