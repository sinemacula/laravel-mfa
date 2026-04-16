<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Contracts;

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
}
