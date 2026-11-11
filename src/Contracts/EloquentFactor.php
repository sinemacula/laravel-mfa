<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Contracts;

use Carbon\CarbonInterface;
use Illuminate\Database\Eloquent\Relations\MorphTo;

/**
 * The persistence side of a factor the services write through; a non-Eloquent
 * factor satisfies `Factor` alone.
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
     * @formatter:off
     *
     * @return \Illuminate\Database\Eloquent\Relations\MorphTo<\Illuminate\Database\Eloquent\Model, \Illuminate\Database\Eloquent\Model>
     *
     * @formatter:on
     */
    public function authenticatable(): MorphTo;

    /**
     * @return string
     */
    public function getTypeName(): string;

    /**
     * @return string
     */
    public function getLabelName(): string;

    /**
     * @return string
     */
    public function getDestinationName(): string;

    /**
     * @return string
     */
    public function getCredentialReferenceName(): string;

    /**
     * @return string
     */
    public function getTotpAlgorithmName(): string;

    /**
     * @return string
     */
    public function getTotpDigitsName(): string;

    /**
     * @return string
     */
    public function getTotpPeriodName(): string;

    /**
     * @return string
     */
    public function getLastAcceptedStepName(): string;

    /**
     * Compare-and-set the step if later than the stored one, persisting at
     * once, so only one of two requests for a step records it.
     *
     * @param  int  $step
     * @return bool
     */
    public function storeAcceptedStep(int $step): bool;

    /**
     * @return string
     */
    public function getStatusName(): string;

    /**
     * @return string
     */
    public function getPreferredName(): string;

    /**
     * @return string
     */
    public function getConsecutiveFailuresName(): string;

    /**
     * A datetime column `Concerns\ActsAsFactor` casts.
     *
     * @return string
     */
    public function getDisabledAtName(): string;

    /**
     * The lockout deadline held on this instance, current only when read under
     * the lock; an unreadable value must throw, never unlock.
     *
     * @return ?\Carbon\CarbonInterface
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\InvalidModelException
     */
    public function getLockedUntil(): ?CarbonInterface;

    /**
     * A datetime column `Concerns\ActsAsFactor` casts.
     *
     * @return string
     */
    public function getLockedUntilName(): string;

    /**
     * @return string
     */
    public function getApplicationName(): string;

    /**
     * @return string
     */
    public function getConfirmedAtName(): string;

    /**
     * @return string
     */
    public function getLastUsedAtName(): string;

    /**
     * Encrypted at rest on the shipped model.
     *
     * @return string
     */
    public function getSecretName(): string;

    /**
     * Mark the factor confirmed at the time given, or now, without persisting.
     *
     * @param  ?\Carbon\CarbonInterface  $at
     * @return void
     */
    public function confirm(?CarbonInterface $at = null): void;

    /**
     * Stamp the last-used time without persisting.
     *
     * @param  ?\Carbon\CarbonInterface  $at
     * @return void
     */
    public function recordVerification(?CarbonInterface $at = null): void;

    /**
     * Anything that stops the write must throw, so the change it is part of
     * rolls back.
     *
     * @return void
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\WriteCanceledException
     */
    public function persist(): void;
}
