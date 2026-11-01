<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Factors;

use Illuminate\Contracts\Container\Container;
use Illuminate\Support\Collection;
use SineMacula\Laravel\Mfa\Database\ConfiguredModels;
use SineMacula\Laravel\Mfa\Database\WriteConnection;
use SineMacula\Laravel\Mfa\Support\CurrentIdentity;

/**
 * Reads the current identity's factors and resolves the configured factor
 * model.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class FactorService
{
    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** The container the configuration is read from. */
        private Container $container,
    ) {}

    /**
     * Determine whether the current identity has at least one registered
     * authentication factor.
     *
     * @return bool
     */
    public function isSetup(): bool
    {
        $identity = CurrentIdentity::resolve();

        if ($identity === null) {
            return false;
        }

        return $identity->isMfaEnabled();
    }

    /**
     * Get the authentication factors for the current identity.
     *
     * Returns null if the identity does not support multi-factor
     * authentication. The factors are read from the write connection (see
     * `Database\WriteConnection`), as they decide verification and lockout, and
     * on every call, so nothing is kept from one request to the next.
     *
     * @formatter:off
     *
     * @return ?\Illuminate\Support\Collection<int, \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\Factor>
     *
     * @formatter:on
     */
    public function getFactors(): ?Collection
    {
        $identity = CurrentIdentity::resolve();

        if ($identity === null) {
            return null;
        }

        return WriteConnection::query($identity->authFactors())->get()->toBase();
    }

    /**
     * Resolve the configured factor model class (see
     * `Database\ConfiguredModels`): the shipped `Factor` model unless
     * `mfa.factor.model` names another, which must extend Eloquent's model and
     * implement `EloquentFactor`.
     *
     * @return class-string<\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor>
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\InvalidModelException
     */
    public function factorModel(): string
    {
        return ConfiguredModels::factor($this->container->make('config'));
    }
}
