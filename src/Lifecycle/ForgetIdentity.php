<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Lifecycle;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Mfa\Contracts\EloquentFactor;
use SineMacula\Laravel\Mfa\Contracts\RecoveryCode;
use SineMacula\Laravel\Mfa\Database\ConfiguredModels;
use SineMacula\Laravel\Mfa\Models\Code;
use SineMacula\Laravel\Mfa\Models\Enrollment;
use SineMacula\Laravel\Mfa\Models\IdentityState;
use SineMacula\Laravel\Mfa\Models\PasskeyAssociation;
use SineMacula\Laravel\Mfa\Support\FactorStateTransaction;
use SineMacula\Laravel\Mfa\Support\IdentityType;

/**
 * Deletes everything the package holds for a deleted identity, under its factor
 * state lock so a change already holding it commits first and is deleted too.
 * Throttles are left to expire: they are keyed by a hash and name no identity.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ForgetIdentity
{
    /**
     * @param  \Illuminate\Contracts\Config\Repository  $config
     */
    public function __construct(

        /** Names the configured factor and recovery code models. */
        private Repository $config,
    ) {}

    /**
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $identity
     * @return void
     *
     * @throws \Throwable
     */
    public function forget(Authenticatable $identity): void
    {
        $factorModel       = ConfiguredModels::factor($this->config);
        $recoveryCodeModel = ConfiguredModels::recoveryCode($this->config);

        $type = IdentityType::of($identity);

        /** @var int|string $key The transaction refuses any other type. */
        $key = $identity->getAuthIdentifier();

        FactorStateTransaction::forIdentity($identity, new $factorModel, static function () use ($factorModel, $recoveryCodeModel, $type, $key): void {

            foreach ([Code::class, Enrollment::class, PasskeyAssociation::class, $recoveryCodeModel, $factorModel, IdentityState::class] as $model) {
                self::owned(new $model, $type, (string) $key)->delete();
            }
        });
    }

    /**
     * Records owned by the identity; an application's factor or recovery code
     * model may name its owner columns differently, so its relation names them.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $model
     * @param  string  $type
     * @param  string  $key
     * @return \Illuminate\Database\Eloquent\Builder<\Illuminate\Database\Eloquent\Model>
     */
    private static function owned(Model $model, string $type, string $key): Builder
    {
        [$typeColumn, $keyColumn] = ['authenticatable_type', 'authenticatable_id'];

        if ($model instanceof EloquentFactor || $model instanceof RecoveryCode) {
            $relation = $model->authenticatable();

            [$typeColumn, $keyColumn] = [$relation->getMorphType(), $relation->getForeignKeyName()];
        }

        return $model->newQuery()
            ->where($typeColumn, $type)
            ->where($keyColumn, $key);
    }
}
