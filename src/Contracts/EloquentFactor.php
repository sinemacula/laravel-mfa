<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Contracts;

use Carbon\CarbonInterface;
use Illuminate\Database\Eloquent\Relations\MorphTo;

/**
 * Explicit persistence boundary for Eloquent-backed factors.
 *
 * Extends the generic `Factor` read surface with the relation and column-name
 * accessors the services use when counting failures, disabling a factor at the
 * failure ceiling, or marking verification — operations that write through to
 * the underlying row and therefore require a persistable implementation.
 *
 * Non-Eloquent implementations (in-memory test doubles, API-backed adapters)
 * satisfy `Factor` alone; the shipped `Factor` model and any consumer subclass
 * intended for persistence satisfy `EloquentFactor`.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @SuppressWarnings("php:S1448")
 */
interface EloquentFactor extends Factor // phpcs:ignore SineMacula.Metrics.MaxMethodCount.TooManyMethods
{
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
     * Column name holding the factor's type.
     *
     * @return string
     */
    public function getTypeName(): string;

    /**
     * Column name holding the human-readable label.
     *
     * @return string
     */
    public function getLabelName(): string;

    /**
     * Column name holding the destination (phone number or email address) of
     * the types that deliver codes to the identity.
     *
     * @return string
     */
    public function getDestinationName(): string;

    /**
     * Column name holding a passkey factor's credential reference.
     *
     * @return string
     */
    public function getCredentialReferenceName(): string;

    /**
     * Column name holding a TOTP factor's HMAC algorithm.
     *
     * @return string
     */
    public function getTotpAlgorithmName(): string;

    /**
     * Column name holding a TOTP factor's number of digits.
     *
     * @return string
     */
    public function getTotpDigitsName(): string;

    /**
     * Column name holding a TOTP factor's period in seconds.
     *
     * @return string
     */
    public function getTotpPeriodName(): string;

    /**
     * Column name holding the last accepted TOTP time step.
     *
     * @return string
     */
    public function getLastAcceptedStepName(): string;

    /**
     * Record the TOTP time step a code was just accepted for, if it is later
     * than the last one accepted, and return whether it was recorded: a
     * compare-and-set of the stored step, so of two requests with a code for
     * the same step only one records it, and a step at or before the stored one
     * is never recorded. Unlike the other mutators it persists at once, as the
     * check and the record are one step; inside a transaction on the storage
     * connection it is part of that transaction.
     *
     * @param  int  $step
     * @return bool
     */
    public function storeAcceptedStep(int $step): bool;

    /**
     * Column name holding the factor's status.
     *
     * @return string
     */
    public function getStatusName(): string;

    /**
     * Column name holding whether the factor is the preferred one.
     *
     * @return string
     */
    public function getPreferredName(): string;

    /**
     * Column name holding the count of consecutive failed verifications.
     *
     * @return string
     */
    public function getConsecutiveFailuresName(): string;

    /**
     * Column name holding when the factor was disabled at the failure ceiling.
     *
     * @return string
     */
    public function getDisabledAtName(): string;

    /**
     * Column name holding the application the factor was enrolled through.
     *
     * @return string
     */
    public function getApplicationName(): string;

    /**
     * Column name holding when the factor was confirmed.
     *
     * @return string
     */
    public function getConfirmedAtName(): string;

    /**
     * Column name holding when the factor was last used.
     *
     * @return string
     */
    public function getLastUsedAtName(): string;

    /**
     * Column name holding the persistent secret (encrypted at rest on the
     * shipped model via the `encrypted` cast).
     *
     * @return string
     */
    public function getSecretName(): string;

    /**
     * Column name holding the pending one-time code.
     *
     * @return string
     */
    public function getCodeName(): string;

    /**
     * Column name holding the expiry of the pending one-time code.
     *
     * @return string
     */
    public function getExpiresAtName(): string;

    /**
     * Column name holding the last-verified timestamp.
     *
     * @return string
     */
    public function getVerifiedAtName(): string;

    /**
     * Mark the factor confirmed, and so usable, at the given time or now. Does
     * not persist: callers invoke `persist()` once the change is complete.
     *
     * @param  ?\Carbon\CarbonInterface  $at
     * @return void
     */
    public function confirm(?CarbonInterface $at = null): void;

    /**
     * Record a successful verification. Stamps the verified-at and last-used
     * timestamps and clears any pending one-time code. Does NOT persist —
     * callers invoke `persist()` once the full orchestration step is complete.
     *
     * @param  ?\Carbon\CarbonInterface  $at
     * @return void
     */
    public function recordVerification(?CarbonInterface $at = null): void;

    /**
     * Persist a newly issued one-time code and its expiry against the factor.
     * Used by OTP-delivery drivers (email, SMS) during challenge issuance. Does
     * NOT save the model — callers invoke `persist()` once the challenge
     * handoff completes.
     *
     * @param  string  $code
     * @param  \Carbon\CarbonInterface  $expiresAt
     * @return void
     */
    public function issueCode(#[\SensitiveParameter] string $code, CarbonInterface $expiresAt): void;

    /**
     * Clear the pending one-time code and its expiry. Called on successful
     * verification to prevent replay within the expiry window and on any
     * driver-side invalidation (e.g. user-initiated reissue).
     *
     * @return void
     */
    public function consumeCode(): void;

    /**
     * Persist any pending mutations to the underlying storage. The shipped
     * Eloquent model delegates to `save()`; consumer implementations can route
     * through their preferred persistence seam.
     *
     * @return void
     */
    public function persist(): void;
}
