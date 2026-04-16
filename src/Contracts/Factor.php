<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Contracts;

use Carbon\CarbonInterface;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Relations\MorphTo;

/**
 * Factor contract.
 *
 * Describes a persisted MFA factor belonging to an authenticatable
 * identity. Drivers type-hint this contract to read their
 * verification inputs (persistent secret, pending one-time code,
 * expiry, attempt state) and the MFA manager uses it to orchestrate
 * verification lifecycle state (attempts, lockouts, verification
 * timestamp).
 *
 * Factor instances are always backed by storage; the default
 * implementation is the shipped `SineMacula\Laravel\Mfa\Models\Factor`
 * Eloquent model, which is swappable via `config('mfa.factor.model')`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 */
interface Factor
{
    /**
     * Return the factor's stable identifier (typically a ULID).
     *
     * @return mixed
     */
    public function getFactorIdentifier(): mixed;

    /**
     * Return the name of the driver this factor is registered
     * against (e.g. `'totp'`, `'email'`, `'sms'`, `'backup_code'`).
     *
     * @return string
     */
    public function getDriver(): string;

    /**
     * Return an optional human-readable label for the factor (e.g.
     * `"Work phone"`, `"Authy"`). Used for UI disambiguation when an
     * identity has multiple factors registered.
     *
     * @return ?string
     */
    public function getLabel(): ?string;

    /**
     * Return the authenticatable the factor belongs to, or `null`
     * when the relation is not loaded or the owner has been detached.
     *
     * @return ?\Illuminate\Contracts\Auth\Authenticatable
     */
    public function getAuthenticatable(): ?Authenticatable;

    /**
     * Polymorphic relation to the owning authenticatable identity.
     *
     * @formatter:off
     *
     * @return \Illuminate\Database\Eloquent\Relations\MorphTo<\Illuminate\Database\Eloquent\Model, \Illuminate\Database\Eloquent\Model>
     *
     * @formatter:on
     */
    public function authenticatable(): MorphTo;

    /**
     * Return the persistent secret for drivers that use one (TOTP);
     * returns `null` for drivers that generate one-time codes on
     * demand (email, SMS, backup codes).
     *
     * @return ?string
     */
    public function getSecret(): ?string;

    /**
     * Return the currently issued one-time code, if any. Used by
     * email / SMS drivers to compare against the submitted code
     * during verification. Returns `null` when no challenge is
     * currently pending or the driver does not use one-time codes.
     *
     * @return ?string
     */
    public function getCode(): ?string;

    /**
     * Return when the currently issued one-time code expires, or
     * `null` when no challenge is pending.
     *
     * @return ?\Carbon\CarbonInterface
     */
    public function getExpiresAt(): ?CarbonInterface;

    /**
     * Return the number of consecutive failed verification attempts
     * against the currently issued challenge / secret.
     *
     * @return int
     */
    public function getAttempts(): int;

    /**
     * Return when the factor is locked until following too many
     * failed attempts, or `null` when the factor is not locked.
     *
     * @return ?\Carbon\CarbonInterface
     */
    public function getLockedUntil(): ?CarbonInterface;

    /**
     * Determine whether the factor is currently locked (i.e.
     * `getLockedUntil()` is in the future).
     *
     * @return bool
     */
    public function isLocked(): bool;

    /**
     * Return when verification was last attempted, regardless of
     * outcome. `null` when the factor has never been exercised.
     *
     * @return ?\Carbon\CarbonInterface
     */
    public function getLastAttemptedAt(): ?CarbonInterface;

    /**
     * Return when the factor was last successfully verified, or
     * `null` when the factor has never completed a successful
     * verification.
     *
     * @return ?\Carbon\CarbonInterface
     */
    public function getVerifiedAt(): ?CarbonInterface;

    /**
     * Determine whether the factor has ever completed a successful
     * verification.
     *
     * @return bool
     */
    public function isVerified(): bool;
}
