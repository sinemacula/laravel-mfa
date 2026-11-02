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
 * Provides the hooks the package needs to query the identity's registered
 * authentication factors, and answers three questions every operation asks
 * first: whether the identity is a person who may hold factors, whether it is
 * active, and what it requires of its own sign-ins. Whether a sign-in needs a
 * further factor is composed from that requirement, the application's
 * configured mode and a re-enrolment obligation, never answered by the identity
 * alone. The `HasFactors` trait gives an Eloquent identity every answer, with
 * the defaults below.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface MultiFactorAuthenticatable extends Authenticatable
{
    /**
     * Determine whether multi-factor authentication is currently enabled for
     * this identity.
     *
     * Canonical rule: MFA is enabled once the identity has at least one factor
     * that is not pending. A pending factor, one whose enrolment has started
     * but not been confirmed, never counts: it can only be confirmed or
     * abandoned. A factor whose stored status is none the package knows does
     * count, so a corrupt status holds the identity to MFA rather than letting
     * it on as having no factor; reading that factor then throws. The
     * `HasFactors` trait implements the rule by reading the factor's status
     * column (`getStatusName()`) from the write connection and counting every
     * value but exactly `FactorStatus::PENDING`'s.
     *
     * What the current sign-in has proved lives separately, in the proof store
     * (`Mfa::proofs()`), so implementations should not fold "has verified" into
     * this predicate: that would collapse two separate concepts.
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
     * (for example, platform staff), in every application whatever its setting,
     * composed with the application's, a tenant's and an operation's; `null`,
     * the default, requires nothing.
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
