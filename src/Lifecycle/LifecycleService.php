<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Lifecycle;

use Illuminate\Contracts\Container\Container;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Mfa\Contracts\Factor;
use SineMacula\Laravel\Mfa\Events\MfaFactorDisabled;
use SineMacula\Laravel\Mfa\Factors\FactorOwnership;
use SineMacula\Laravel\Mfa\Factors\FactorStateCache;
use SineMacula\Laravel\Mfa\Support\CurrentIdentity;

/**
 * Removes the current identity's factors.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class LifecycleService
{
    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  \SineMacula\Laravel\Mfa\Factors\FactorStateCache  $cache
     */
    public function __construct(

        /** The container the event dispatcher is read from. */
        private Container $container,

        /** The per-request cache of the identity's factor state. */
        private FactorStateCache $cache,
    ) {}

    /**
     * Disable a previously-enrolled factor for the current identity.
     *
     * Deletes the underlying row when the factor is an Eloquent model,
     * invalidates the setup-state cache, and dispatches `MfaFactorDisabled`.
     * Non-Eloquent factors are left for the consumer to discard; the event
     * still fires.
     *
     * Throws `FactorOwnershipMismatchException` when the factor does not belong
     * to the current identity. No-op when no MFA-capable identity is
     * resolvable.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\FactorOwnershipMismatchException
     */
    public function disable(Factor $factor): void
    {
        $identity = CurrentIdentity::resolve();

        if ($identity === null) {
            return;
        }

        FactorOwnership::assert($factor, $identity);

        if ($factor instanceof Model) {
            $factor->delete();
        }

        $this->cache->clear($identity);

        $events = $this->container->make(Dispatcher::class);
        $events->dispatch(new MfaFactorDisabled($identity, $factor, $factor->getType()));
    }
}
