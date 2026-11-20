<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Lifecycle;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Config\Repository;
use SineMacula\Laravel\Mfa\Database\ConfiguredModels;
use SineMacula\Laravel\Mfa\Models\Code;
use SineMacula\Laravel\Mfa\Models\Enrollment;
use SineMacula\Laravel\Mfa\Models\IdentityState;
use SineMacula\Laravel\Mfa\Models\PasskeyAssociation;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;
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

        /** @var int|string $key The transaction refuses any other type. */
        $key  = $identity->getAuthIdentifier();
        $hash = (new ProofOwner(IdentityType::of($identity), (string) $key))->hash();

        FactorStateTransaction::forIdentity($identity, new $factorModel, static function () use ($factorModel, $recoveryCodeModel, $hash): void {

            foreach ([Code::class, Enrollment::class, PasskeyAssociation::class, $recoveryCodeModel, $factorModel, IdentityState::class] as $model) {
                $owned = new $model;

                $owned->newQuery()->where($owned->getOwnerHashName(), $hash)->delete();
            }
        });
    }
}
