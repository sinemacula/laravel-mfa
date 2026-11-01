<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Enrollment;

use Illuminate\Contracts\Container\Container;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Mfa\Contracts\EloquentFactor;
use SineMacula\Laravel\Mfa\Contracts\Factor;
use SineMacula\Laravel\Mfa\Events\MfaFactorEnrolled;
use SineMacula\Laravel\Mfa\Factors\FactorOwnership;
use SineMacula\Laravel\Mfa\Factors\FactorStateCache;
use SineMacula\Laravel\Mfa\Support\CurrentIdentity;

/**
 * Enrols factors for the current identity.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class EnrollmentService
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
     * Enrol a freshly-built factor against the current identity.
     *
     * The consumer constructs the factor (with secret/recipient/hash already
     * populated); this method stamps ownership onto the current identity,
     * persists via `EloquentFactor::persist()`, invalidates the setup-state
     * cache, and dispatches `MfaFactorEnrolled`.
     *
     * Ownership is stamped, never trusted: caller-supplied morph columns on an
     * Eloquent factor are overwritten so a consumer cannot enrol a factor
     * against a different account. Non-Eloquent factor implementations must
     * already report the current identity through `getAuthenticatable()`;
     * mismatches throw `FactorOwnershipMismatchException`.
     *
     * No-op when no MFA-capable identity is resolvable, matching the
     * `markVerified()` / `forgetVerification()` shape so consumers can call
     * this unconditionally.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\FactorOwnershipMismatchException
     */
    public function enroll(Factor $factor): void
    {
        $identity = CurrentIdentity::resolve();

        if ($identity === null) {
            return;
        }

        if ($factor instanceof EloquentFactor && $factor instanceof Model) {
            // Stamping ownership only makes sense for a brand-new factor. If
            // the row already exists (e.g. the consumer fetched it by primary
            // key from request input) we MUST NOT silently overwrite its morph
            // columns: that would let an attacker hijack any factor row whose
            // ID they could enumerate. Treat an existing row as an attempt to
            // re-enrol it under the current identity and require ownership to
            // already match.
            if ($factor->exists) {
                FactorOwnership::assert($factor, $identity);
            } else {
                $relation = $factor->authenticatable();

                $factor->setAttribute($relation->getMorphType(), CurrentIdentity::typeOf($identity));
                $factor->setAttribute($relation->getForeignKeyName(), $identity->getAuthIdentifier());
            }

            $factor->persist();
        } else {
            FactorOwnership::assert($factor, $identity);
        }

        $this->cache->clear($identity);

        $events = $this->container->make(Dispatcher::class);
        $events->dispatch(new MfaFactorEnrolled($identity, $factor, $factor->getDriver()));
    }
}
