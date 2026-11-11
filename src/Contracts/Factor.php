<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Contracts;

use Carbon\CarbonInterface;
use SineMacula\Laravel\Mfa\Enums\FactorStatus;

/**
 * The read surface of one enrolled factor, so drivers work with the shipped
 * model, a consumer's own or a test double.
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
     * Opaque and non-sequential (a ULID on the shipped model).
     *
     * @return mixed
     */
    public function getFactorIdentifier(): mixed;

    /**
     * The name the type's driver is registered under, such as `totp`.
     *
     * @return string
     */
    public function getType(): string;

    /**
     * @return ?string
     */
    public function getLabel(): ?string;

    /**
     * An E.164 number or email address captured at enrolment; `null` for other
     * types.
     *
     * @return ?string
     */
    public function getDestination(): ?string;

    /**
     * The passkey credential the factor is associated with; `null` for other
     * types.
     *
     * @return ?string
     */
    public function getCredentialReference(): ?string;

    /**
     * The TOTP shared secret, if any.
     *
     * @return ?string
     */
    public function getSecret(): ?string;

    /**
     * `sha1`, `sha256` or `sha512`; `null` for other types.
     *
     * @return ?string
     */
    public function getTotpAlgorithm(): ?string;

    /**
     * `null` for other types.
     *
     * @return ?int
     */
    public function getTotpDigits(): ?int;

    /**
     * In seconds; `null` for other types.
     *
     * @return ?int
     */
    public function getTotpPeriod(): ?int;

    /**
     * The last TOTP step accepted, so it and earlier steps are refused; `null`
     * before the first.
     *
     * @return ?int
     */
    public function getLastAcceptedStep(): ?int;

    /**
     * An unknown stored value must throw, never read as pending, since that can
     * let a weaker path through.
     *
     * @return \SineMacula\Laravel\Mfa\Enums\FactorStatus
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\InvalidModelException
     */
    public function getStatus(): FactorStatus;

    /**
     * @return bool
     */
    public function isConfirmed(): bool;

    /**
     * The preferred factor is offered first.
     *
     * @return bool
     */
    public function isPreferred(): bool;

    /**
     * Kept until this factor next succeeds.
     *
     * @return int
     */
    public function getConsecutiveFailures(): int;

    /**
     * When the failure ceiling disabled the factor; an unreadable value must
     * throw, never read as `null`, which would enable it.
     *
     * @return ?\Carbon\CarbonInterface
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\InvalidModelException
     */
    public function getDisabledAt(): ?CarbonInterface;

    /**
     * The application its enrolment limits count it against.
     *
     * @return ?string
     */
    public function getApplication(): ?string;

    /**
     * `null` while pending.
     *
     * @return ?\Carbon\CarbonInterface
     */
    public function getConfirmedAt(): ?CarbonInterface;

    /**
     * `null` before its first use.
     *
     * @return ?\Carbon\CarbonInterface
     */
    public function getLastUsedAt(): ?CarbonInterface;
}
