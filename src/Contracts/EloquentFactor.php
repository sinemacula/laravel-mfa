<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Contracts;

use Carbon\CarbonInterface;
use Illuminate\Database\Eloquent\Relations\MorphTo;

/**
 * Explicit persistence boundary for Eloquent-backed factors.
 *
 * Extends the generic `Factor` read surface with the relation and column-name
 * accessors the manager orchestration layer uses when incrementing attempts,
 * applying lockouts, or marking verification — operations that write through
 * to the underlying row and therefore require a persistable implementation.
 *
 * Non-Eloquent implementations (in-memory test doubles, API-backed adapters)
 * satisfy `Factor` alone; the shipped `Factor` model and any consumer
 * subclass intended for persistence satisfy `EloquentFactor`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 */
interface EloquentFactor extends Factor
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
     * Column name holding the driver identifier.
     *
     * @return string
     */
    public function getDriverName(): string;

    /**
     * Column name holding the human-readable label.
     *
     * @return string
     */
    public function getLabelName(): string;

    /**
     * Column name holding the delivery destination (phone number / email)
     * for drivers that deliver codes to the identity.
     *
     * @return string
     */
    public function getRecipientName(): string;

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
     * Column name holding the failed-attempt counter.
     *
     * @return string
     */
    public function getAttemptsName(): string;

    /**
     * Column name holding the lockout expiry timestamp.
     *
     * @return string
     */
    public function getLockedUntilName(): string;

    /**
     * Column name holding the last-attempted timestamp.
     *
     * @return string
     */
    public function getLastAttemptedAtName(): string;

    /**
     * Column name holding the last-verified timestamp.
     *
     * @return string
     */
    public function getVerifiedAtName(): string;

    /**
     * Record a new verification attempt against the factor. Increments the
     * attempt counter and stamps the last-attempted timestamp. Does NOT
     * persist — callers invoke `persist()` once the full orchestration
     * step is complete.
     *
     * @param  ?\Carbon\CarbonInterface  $at
     * @return void
     */
    public function recordAttempt(?CarbonInterface $at = null): void;

    /**
     * Reset the attempt counter and clear any active lockout. Called after
     * a successful verification or on a fresh challenge issuance.
     *
     * @return void
     */
    public function resetAttempts(): void;

    /**
     * Apply a lockout window, deferring further verification attempts until
     * the given timestamp. Orthogonal to `recordAttempt()`; callers may
     * lock after recording an attempt that crosses the max-attempts
     * threshold.
     *
     * @param  \Carbon\CarbonInterface  $until
     * @return void
     */
    public function applyLockout(CarbonInterface $until): void;

    /**
     * Record a successful verification. Stamps the verified-at timestamp,
     * resets attempts, and clears any pending one-time code. Does NOT
     * persist — callers invoke `persist()` once the full orchestration
     * step is complete.
     *
     * @param  ?\Carbon\CarbonInterface  $at
     * @return void
     */
    public function recordVerification(?CarbonInterface $at = null): void;

    /**
     * Persist a newly issued one-time code and its expiry against the
     * factor. Used by OTP-delivery drivers (email, SMS) during challenge
     * issuance. Does NOT save the model — callers invoke `persist()` once
     * the challenge handoff completes.
     *
     * @param  string  $code
     * @param  \Carbon\CarbonInterface  $expiresAt
     * @return void
     */
    public function issueCode(
        #[\SensitiveParameter]
        string $code,
        CarbonInterface $expiresAt,
    ): void;

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
     * Eloquent model delegates to `save()`; consumer implementations can
     * route through their preferred persistence seam.
     *
     * @return void
     */
    public function persist(): void;
}
