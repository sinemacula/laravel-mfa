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
 * Deletes everything the package holds for a deleted identity: its factors,
 * enrolments in progress, delivered codes, recovery codes, passkey associations
 * and factor state.
 *
 * The `HasFactors` trait calls it once an Eloquent identity's row is deleted;
 * an application whose identities are not Eloquent models calls
 * `Mfa::forgetIdentity()`, after deleting the identity. It runs in the
 * identity's factor state transaction (see `Support\FactorStateTransaction`),
 * so nothing is left half deleted and a change already holding the identity's
 * lock commits first and is deleted with the rest; called inside a transaction
 * on the storage connection, it joins it. The temporary throttles are left to
 * expire: they are keyed by a hash and hold nothing that names the identity.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ForgetIdentity
{
    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     */
    public function __construct(

        /** The configuration the models are read from. */
        private Repository $config,
    ) {}

    /**
     * Delete everything the package holds for the identity.
     *
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

        /** @var int|string $key Refused by the transaction when it is anything else. */
        $key = $identity->getAuthIdentifier();

        FactorStateTransaction::forIdentity($identity, new $factorModel, static function () use ($factorModel, $recoveryCodeModel, $type, $key): void {

            foreach ([Code::class, Enrollment::class, PasskeyAssociation::class, $recoveryCodeModel, $factorModel, IdentityState::class] as $model) {
                self::owned(new $model, $type, (string) $key)->delete();
            }
        });
    }

    /**
     * The model's records owned by the identity, found by its owner columns:
     * those of its owner relation for a factor or recovery code model, which an
     * application's own model may name differently, and the package's own
     * otherwise.
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
