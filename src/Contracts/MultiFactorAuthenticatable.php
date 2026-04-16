<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Builder;

/**
 * Multi-factor authenticatable contract.
 *
 * Implemented by identity models that support multi-factor
 * authentication. Provides the hooks needed by the MFA manager
 * to determine whether MFA should be applied and to query the
 * identity's registered authentication factors.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 */
interface MultiFactorAuthenticatable extends Authenticatable
{
    /**
     * Determine whether multi-factor authentication should be used
     * for this identity.
     *
     * This is the primary gate: if it returns false, MFA checks are
     * bypassed entirely for this identity.
     *
     * @return bool
     */
    public function shouldUseMultiFactor(): bool;

    /**
     * Determine whether multi-factor authentication is currently
     * enabled for this identity.
     *
     * An identity may support MFA but not yet have it enabled
     * (e.g. the user hasn't configured any factors).
     *
     * @return bool
     */
    public function isMfaEnabled(): bool;

    /**
     * Retrieve the authentication factors for this identity.
     *
     * Returns an Eloquent builder so the caller can apply further
     * constraints (e.g. filtering by verified factors). The
     * underlying model MUST implement the package `Factor` contract
     * (the shipped `Factor` model does; custom models applied via
     * `config('mfa.factor.model')` must too).
     *
     * @formatter:off
     *
     * @return \Illuminate\Database\Eloquent\Builder<\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\Factor>
     *
     * @formatter:on
     */
    public function authFactors(): Builder;
}
