<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Builder;

/**
 * Multi-factor authenticatable contract.
 *
 * Implemented by identity models that support multi-factor authentication.
 * Provides the hooks needed by the MFA manager to determine whether MFA should
 * be applied and to query the identity's registered authentication factors.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 */
interface MultiFactorAuthenticatable extends Authenticatable
{
    /**
     * Determine whether multi-factor authentication should be used for this
     * identity.
     *
     * This is the primary gate: if it returns false, MFA checks are bypassed
     * entirely for this identity.
     *
     * @return bool
     */
    public function shouldUseMultiFactor(): bool;

    /**
     * Determine whether multi-factor authentication is currently enabled for
     * this identity.
     *
     * Canonical rule: MFA is enabled once the identity has at least one
     * enrolled factor. Per-request verification freshness lives separately on
     * `Mfa::hasExpired()` / the verification store, so implementations should
     * NOT fold "has ever verified" into this predicate — that would collapse
     * two orthogonal concepts and leave newly enrolled factors reading as
     * "not enabled".
     *
     * Consumers whose product policy is stricter (e.g. "enabled" means the
     * factor has completed its first verification) may implement that
     * narrower rule here; the package does not enforce a single query shape.
     * The shipped `Mfa::isSetup()` caches and reports whatever this method
     * returns.
     *
     * @return bool
     */
    public function isMfaEnabled(): bool;

    /**
     * Retrieve the authentication factors for this identity.
     *
     * Returns an Eloquent builder so the caller can apply further constraints
     * (e.g. filtering by verified factors). The underlying model MUST implement
     * the package `Factor` contract (the shipped `Factor` model does; custom
     * models applied via `config('mfa.factor.model')` must too).
     *
     * @formatter:off
     *
     * @return \Illuminate\Database\Eloquent\Builder<\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\Factor>
     *
     * @formatter:on
     */
    public function authFactors(): Builder;
}
