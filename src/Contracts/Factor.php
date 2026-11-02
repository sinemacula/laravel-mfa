<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Contracts;

use Carbon\CarbonInterface;
use SineMacula\Laravel\Mfa\Enums\FactorStatus;

/**
 * Factor contract.
 *
 * The read surface of one enrolled factor: its opaque id, its type (the name
 * its driver is registered under), the label the person chose, its destination
 * (SMS and email) or credential reference (passkey), its secret and TOTP
 * parameters, its status, whether it is the preferred factor, its durable
 * failure state, the application it was enrolled through, and when it was
 * confirmed and last used. Drivers type-hint this contract, so the same logic
 * applies to the shipped Eloquent model, a consumer's own model, or a test
 * double.
 *
 * The last verification time is still read here until the proof store replaces
 * it with a record of its own. Delivered codes have a record of their own. A
 * lockout is not read here: only a factor with a row of its own can hold a
 * deadline (see `EloquentFactor`), and the attempt service answers for every
 * scope (see `Attempts\AttemptService::lockout()`).
 *
 * Persistence-capable implementations also implement the narrower
 * `EloquentFactor` boundary, which adds the owner relation, the column names
 * and the mutators the services write through.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @SuppressWarnings("php:S1448")
 */
interface Factor // phpcs:ignore SineMacula.Metrics.MaxMethodCount.TooManyMethods
{
    /**
     * Return the factor's opaque, non-sequential identifier (a ULID on the
     * shipped model).
     *
     * @return mixed
     */
    public function getFactorIdentifier(): mixed;

    /**
     * Return the factor's type: the name its driver is registered under with
     * the manager (for example `totp`, `email` or `sms`).
     *
     * @return string
     */
    public function getType(): string;

    /**
     * Return the label the person chose for the factor, if any.
     *
     * @return ?string
     */
    public function getLabel(): ?string;

    /**
     * Return the destination an SMS or email factor delivers to (an E.164 phone
     * number or an email address), captured at enrolment; `null` for any other
     * type.
     *
     * @return ?string
     */
    public function getDestination(): ?string;

    /**
     * Return the reference of the credential a passkey factor is associated
     * with; `null` for any other type.
     *
     * @return ?string
     */
    public function getCredentialReference(): ?string;

    /**
     * Return the factor's persistent secret (the TOTP shared secret), if any.
     *
     * @return ?string
     */
    public function getSecret(): ?string;

    /**
     * Return the HMAC algorithm of a TOTP factor (`sha1`, `sha256` or
     * `sha512`), stored when it is enrolled; `null` for any other type.
     *
     * @return ?string
     */
    public function getTotpAlgorithm(): ?string;

    /**
     * Return the number of digits of a TOTP factor's codes, stored when it is
     * enrolled; `null` for any other type.
     *
     * @return ?int
     */
    public function getTotpDigits(): ?int;

    /**
     * Return the period of a TOTP factor's time steps in seconds, stored when
     * it is enrolled; `null` for any other type.
     *
     * @return ?int
     */
    public function getTotpPeriod(): ?int;

    /**
     * Return the last time step a TOTP code was accepted for, so the same or an
     * earlier step is refused; `null` before the first.
     *
     * @return ?int
     */
    public function getLastAcceptedStep(): ?int;

    /**
     * Return where the factor is in its enrolment. A stored value that is none
     * of the statuses must throw, never read as pending, since a factor read as
     * not confirmed can let a weaker path through.
     *
     * @return \SineMacula\Laravel\Mfa\Enums\FactorStatus
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\InvalidModelException
     */
    public function getStatus(): FactorStatus;

    /**
     * Determine whether the factor is confirmed, and so usable.
     *
     * @return bool
     */
    public function isConfirmed(): bool;

    /**
     * Determine whether the factor is the identity's preferred one, offered
     * first.
     *
     * @return bool
     */
    public function isPreferred(): bool;

    /**
     * Return the factor's count of consecutive failed verifications, kept until
     * a success of this factor.
     *
     * @return int
     */
    public function getConsecutiveFailures(): int;

    /**
     * Return when the factor was disabled for reaching the failure ceiling, or
     * `null` while it is not. A stored value that does not read as a time must
     * throw, never read as `null`, since that would enable the factor.
     *
     * @return ?\Carbon\CarbonInterface
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\InvalidModelException
     */
    public function getDisabledAt(): ?CarbonInterface;

    /**
     * Return the application the factor was enrolled through, which its limits
     * on new enrolments count it against.
     *
     * @return ?string
     */
    public function getApplication(): ?string;

    /**
     * Return when the factor was confirmed, or `null` while it is pending.
     *
     * @return ?\Carbon\CarbonInterface
     */
    public function getConfirmedAt(): ?CarbonInterface;

    /**
     * Return when the factor was last used to verify, or `null` before its
     * first use.
     *
     * @return ?\Carbon\CarbonInterface
     */
    public function getLastUsedAt(): ?CarbonInterface;
}
