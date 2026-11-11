<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Builder;
use SineMacula\Laravel\Mfa\Requirements\Requirement;

/**
 * An identity model that supports multi-factor authentication; the `HasFactors`
 * trait implements it for Eloquent.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface MultiFactorAuthenticatable extends Authenticatable
{
    /**
     * True once the identity has a factor that is not pending; an unknown
     * status counts, so a corrupt row holds the identity to MFA.
     *
     * @return bool
     */
    public function isMfaEnabled(): bool;

    /**
     * A person may, a machine (an API client or service account) may not.
     *
     * @return bool
     */
    public function canHoldFactors(): bool;

    /**
     * An inactive identity cannot enrol, verify or use a recovery code.
     *
     * @return bool
     */
    public function isMfaActive(): bool;

    /**
     * What the identity requires of its own sign-ins in every application, or
     * `null` for nothing.
     *
     * @return ?\SineMacula\Laravel\Mfa\Requirements\Requirement
     */
    public function requiresAdditionalFactor(): ?Requirement;

    /**
     * The model behind the builder must implement the `Factor` contract.
     *
     * @formatter:off
     *
     * @return \Illuminate\Database\Eloquent\Builder<\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\Factor>
     *
     * @formatter:on
     */
    public function authFactors(): Builder;
}
