<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Concerns;

use Illuminate\Container\Container;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Mfa\Database\ConfiguredModels;
use SineMacula\Laravel\Mfa\Enums\FactorStatus;
use SineMacula\Laravel\Mfa\Lifecycle\ForgetIdentity;
use SineMacula\Laravel\Mfa\Requirements\Requirement;

/**
 * What an Eloquent identity model needs to hold factors, used with the
 * `MultiFactorAuthenticatable` contract: its factors, whether it has a
 * confirmed one, and the defaults of the questions every operation asks first
 * (a person, active, requiring nothing of its own), which the model overrides
 * where its own state answers them. Deleting the model deletes everything the
 * package holds for it (see `Lifecycle\ForgetIdentity`).
 *
 * The factors are those of the configured factor model, owned through the
 * polymorphic `authenticatable` relation.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @phpstan-require-extends \Illuminate\Database\Eloquent\Model
 */
trait HasFactors
{
    /**
     * Delete everything the package holds for the identity as it is deleted:
     * its factors, enrolments, delivered codes, recovery codes, passkey
     * associations and factor state.
     *
     * @return void
     */
    public static function bootHasFactors(): void
    {
        static::deleting(static function (Model $identity): void {

            if (!$identity instanceof Authenticatable) {
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
     * Determine whether the identity has a confirmed factor: a pending one does
     * not count.
     *
     * @return bool
     */
    public function isMfaEnabled(): bool
    {
        $factor = $this->authFactors()->getModel();

        // @phpstan-ignore method.notFound
        return $this->authFactors()->where($factor->getStatusName(), FactorStatus::CONFIRMED->value)->exists();
    }

    /**
     * The identity's factors, of the configured factor model.
     *
     * @formatter:off
     *
     * @return \Illuminate\Database\Eloquent\Builder<\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\Factor>
     *
     * @formatter:on
     */
    public function authFactors(): Builder
    {
        $model = ConfiguredModels::factor(Container::getInstance()->make('config'));

        /** @var \Illuminate\Database\Eloquent\Builder<\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\Factor> */
        return $this->morphMany($model, 'authenticatable')->getQuery();
    }
}
