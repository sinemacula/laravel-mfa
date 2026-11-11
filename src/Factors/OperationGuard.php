<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Factors;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Container\Container;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Mfa\Applications\ApplicationSettings;
use SineMacula\Laravel\Mfa\Contracts\ActiveStateResolver;
use SineMacula\Laravel\Mfa\Contracts\EloquentFactor;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\SubjectTypeResolver;
use SineMacula\Laravel\Mfa\Database\ConfiguredModels;
use SineMacula\Laravel\Mfa\Database\WriteConnection;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException;
use SineMacula\Laravel\Mfa\Support\FactorOwnerColumns;
use SineMacula\Laravel\Mfa\Support\IdentityType;

/**
 * The guard every operation on an identity's factors starts with, so each
 * refuses the same things in the same order with the same reasons.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class OperationGuard
{
    /**
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** Read per call. */
        private Repository $config,

        /** Resolves the seams per call. */
        private Container $container,
    ) {}

    /**
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     */
    public function identity(MultiFactorAuthenticatable $identity): void
    {
        if (!$this->container->make(SubjectTypeResolver::class)->isPerson($identity)) {
            throw OperationRefusedException::byPackage(FailureReason::MACHINE_IDENTITY, 'The identity is not a person, so it cannot hold factors.');
        }

        if (!$this->container->make(ActiveStateResolver::class)->isActive($identity)) {
            throw OperationRefusedException::byPackage(FailureReason::IDENTITY_INACTIVE, 'The identity is inactive.');
        }
    }

    /**
     * Another person's factor id is `not_found`, as one that does not exist.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  mixed  $factorId
     * @param  string  $application
     * @param  bool  $confirmed
     * @return \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     */
    public function factor(MultiFactorAuthenticatable $identity, mixed $factorId, string $application, bool $confirmed = true): EloquentFactor&Model
    {
        $this->identity($identity);

        $factor = $this->find($identity, $factorId) ?? throw OperationRefusedException::byPackage(FailureReason::NOT_FOUND, 'The identity has no factor with that id.');

        if ($confirmed && !$factor->isConfirmed()) {
            throw OperationRefusedException::byPackage(FailureReason::NOT_CONFIRMED, 'The factor is pending, and the operation needs a confirmed one.');
        }

        if (!(new ApplicationSettings($this->config, $application))->enables($factor->getType())) {
            throw OperationRefusedException::byPackage(FailureReason::TYPE_NOT_ENABLED, sprintf('The application does not enable the factor\'s type [%s].', $factor->getType()));
        }

        return $factor;
    }

    /**
     * Read from the write connection and matched exactly, as a collation may
     * match an owner or id differing only in case.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  mixed  $factorId
     * @return (\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor)|null
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\InvalidModelException
     */
    private function find(MultiFactorAuthenticatable $identity, mixed $factorId): (EloquentFactor&Model)|null
    {
        $key = $identity->getAuthIdentifier();

        if ((!is_string($factorId) && !is_int($factorId)) || (!is_string($key) && !is_int($key))) {
            return null;
        }

        $model = ConfiguredModels::factor($this->config);
        $blank = new $model;

        [$typeColumn, $keyColumn] = FactorOwnerColumns::of($blank);

        $type = IdentityType::of($identity);

        /** @var (\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor)|null $factor */
        $factor = WriteConnection::query($blank->newQuery())
            ->where($typeColumn, $type)
            ->where($keyColumn, (string) $key)
            ->whereKey($factorId)
            ->first();

        if ($factor === null || !FactorOwnerColumns::owns($factor, $type, (string) $key)) {
            return null;
        }

        /** @var int|string $stored */
        $stored = $factor->getKey();

        return (string) $stored === (string) $factorId ? $factor : null;
    }
}
