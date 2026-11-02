<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Factors;

use Illuminate\Contracts\Container\Container;
use Illuminate\Support\Collection;
use SineMacula\Laravel\Mfa\Context\CallerContextResolver;
use SineMacula\Laravel\Mfa\Database\ConfiguredModels;
use SineMacula\Laravel\Mfa\Database\WriteConnection;
use SineMacula\Laravel\Mfa\Enums\PendingAction;

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
     * Determine whether the signed-in person has at least one registered
     * authentication factor; `false` on a pending session, and without an
     * MFA-capable person (see `Context\CallerContextResolver`).
     *
     * @return bool
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function isSetup(): bool
    {
        $identity = $this->container->make(CallerContextResolver::class)->resolve(null)?->identity;

        if ($identity === null) {
            return false;
        }

        return $identity->isMfaEnabled();
    }

    /**
     * Get the authentication factors of the identity the request serves for
     * listing factors (see `Context\CallerContextResolver`): a pending
     * session's when its credential allows listing them, otherwise the
     * signed-in person's.
     *
     * Returns null when the request serves nobody for listing factors: a
     * pending session that does not allow it, no MFA-capable identity, or one
     * that is not a person. The factors are read from the write connection (see
     * `Database\WriteConnection`), as they decide verification and lockout, and
     * on every call, so nothing is kept from one request to the next.
     *
     * @formatter:off
     *
     * @return ?\Illuminate\Support\Collection<int, \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\Factor>
     *
     * @formatter:on
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function getFactors(): ?Collection
    {
        $caller = $this->container->make(CallerContextResolver::class)->resolve(PendingAction::LIST_FACTORS);

        if ($caller === null) {
            return null;
        }

        return WriteConnection::query($caller->identity->authFactors())->get()->toBase();
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
