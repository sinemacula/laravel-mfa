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
    /** @var string Cache key for the setup state */
    private const string CACHE_KEY_SETUP = 'setup';

    /** @var string Cache key for the factors collection */
    private const string CACHE_KEY_FACTORS = 'factors';

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  \SineMacula\Laravel\Mfa\Factors\FactorStateCache  $cache
     */
    public function __construct(

        /** The container the configuration is read from. */
        private Container $container,

        /** The per-request cache of the identity's factor state. */
        private FactorStateCache $cache,
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

        /** @var bool */
        return $this->cache->remember($identity, self::CACHE_KEY_SETUP, static fn (): bool => $identity->isMfaEnabled());
    }

    /**
     * Get the authentication factors for the current identity.
     *
     * Returns null if the identity does not support multi-factor
     * authentication. The factors are read from the write connection (see
     * `Database\WriteConnection`), as they decide verification and lockout. The
     * result is cached for the duration of the request.
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

        /** @var \Illuminate\Support\Collection<int, \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\Factor> */
        return $this->cache->remember($identity, self::CACHE_KEY_FACTORS, static fn (): Collection => WriteConnection::query($identity->authFactors())->get()->toBase());
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
