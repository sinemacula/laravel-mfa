<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Builder;
use SineMacula\Laravel\Mfa\Requirements\Requirement;

/**
 * Multi-factor authenticatable contract.
 *
 * Implemented by identity models that support multi-factor authentication.
 * Provides the hooks needed by the MFA manager to determine whether MFA should
 * be applied and to query the identity's registered authentication factors, and
 * answers three questions every operation asks first: whether the identity is a
 * person who may hold factors, whether it is active, and what it requires of
 * its own sign-ins. The `HasFactors` trait gives an Eloquent identity every
 * answer but `shouldUseMultiFactor()`, with the defaults below.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
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
     * confirmed factor. A pending factor, one whose enrolment has started but
     * not been confirmed, never counts: it can only be confirmed or abandoned.
     * The `HasFactors` trait implements the rule by filtering the identity's
     * factors on the factor's status column (`getStatusName()`) holding
     * `FactorStatus::CONFIRMED`, read from the write connection.
     *
     * What the current sign-in has proved lives separately, in the proof store
     * (`Mfa::proofs()`), so implementations should not fold "has verified" into
     * this predicate: that would collapse two separate concepts. The shipped
     * `Mfa::isSetup()` reports whatever this method returns.
     *
     * @return bool
     */
    public function isMfaEnabled(): bool;

    /**
     * Determine whether the identity may hold factors: a person may, a machine
     * (an API client or service account) may not, and every operation refuses
     * it. With an authentication layer this is its subject type.
     *
     * @return bool
     */
    public function canHoldFactors(): bool;

    /**
     * Determine whether the identity is active. An inactive identity cannot
     * enrol, verify or use a recovery code. With an authentication layer this
     * is its active state; alone, the default treats every identity the guard
     * returns as active.
     *
     * @return bool
     */
    public function isMfaActive(): bool;

    /**
     * The additional verification the identity requires of its own sign-ins
     * (for example, platform staff), composed with the application's, a
     * tenant's and an operation's; `null`, the default, requires nothing.
     *
     * @return ?\SineMacula\Laravel\Mfa\Requirements\Requirement
     */
    public function requiresAdditionalFactor(): ?Requirement;

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
