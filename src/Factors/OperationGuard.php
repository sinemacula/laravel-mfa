<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Factors;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Container\Container;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Mfa\Applications\ApplicationSettings;
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
 * The one guard every operation on an identity's factors starts with, so each
 * refuses the same things in the same order with the same reasons:
 *
 * 1. a machine identity, which cannot hold factors (`machine_identity`), as
 *    the bound `SubjectTypeResolver` decides;
 * 2. an inactive identity (`identity_inactive`);
 * 3. a factor that is not the identity's (`not_found`): its id is only ever
 *    looked up within the identity, so another person's factor id finds
 *    nothing, exactly as an id that does not exist;
 * 4. a pending factor where the operation needs a confirmed one
 *    (`not_confirmed`);
 * 5. a factor whose type the application does not enable (`type_not_enabled`).
 *
 * A refusal throws an `OperationRefusedException` carrying the reason. The
 * factor is read from the write connection, as everything that decides
 * verification is.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class OperationGuard
{
    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** The configuration the factor model and applications are read from. */
        private Repository $config,

        /** The container the subject type resolver is read from. */
        private Container $container,
    ) {}

    /**
     * Refuse an identity that may not hold factors or is inactive.
     *
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

        if (!$identity->isMfaActive()) {
            throw OperationRefusedException::byPackage(FailureReason::IDENTITY_INACTIVE, 'The identity is inactive.');
        }
    }

    /**
     * Refuse the identity as `identity()` does, then return its factor with the
     * given id, refusing one it does not own, a pending one unless the
     * operation takes pending factors, and one whose type the application does
     * not enable.
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
     * The identity's factor with the given id, looked up within the identity
     * only, or `null`. An id that is neither a string nor an integer finds
     * nothing. A database's collation may match an owner or an id differing
     * only in case, so the row found must hold exactly what was asked for.
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

        /** @var int|string $stored A row found by its key has one of these. */
        $stored = $factor->getKey();

        return (string) $stored === (string) $factorId ? $factor : null;
    }
}
