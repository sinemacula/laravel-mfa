<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Contracts;

use Carbon\CarbonInterface;
use Illuminate\Database\Eloquent\Relations\MorphTo;

/**
 * Recovery code contract.
 *
 * One code of an identity's recovery code set, stored as a salted hash: its
 * owner, the generation of the set it belongs to, and when it was used or
 * replaced by a newer set. A code is usable only while it is neither. The
 * shipped `RecoveryCode` model implements it through the `ActsAsRecoveryCode`
 * trait; an application may configure a subclass or its own Eloquent model
 * (`mfa.recovery_codes.model`) that does the same.
 *
 * Column names are exposed through the `get*Name()` methods, so a model can
 * remap a column without overriding its accessor.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface RecoveryCode
{
    /**
     * Polymorphic relation to the identity the code belongs to.
     *
     * @formatter:off
     *
     * @return \Illuminate\Database\Eloquent\Relations\MorphTo<\Illuminate\Database\Eloquent\Model, \Illuminate\Database\Eloquent\Model>
     *
     * @formatter:on
     */
    public function authenticatable(): MorphTo;

    /**
     * Return the salted hash of the code, never the code itself.
     *
     * @return ?string
     */
    public function getCodeHash(): ?string;

    /**
     * Return when the code was used, or `null` while it is unused.
     *
     * @return ?\Carbon\CarbonInterface
     */
    public function getUsedAt(): ?CarbonInterface;

    /**
     * Return when a newer set replaced the code's set, or `null` while it has
     * not.
     *
     * @return ?\Carbon\CarbonInterface
     */
    public function getReplacedAt(): ?CarbonInterface;

    /**
     * Determine whether the code can still be redeemed: neither used nor
     * replaced.
     *
     * @return bool
     */
    public function isUsable(): bool;

    /**
     * Column name holding the code's hash.
     *
     * @return string
     */
    public function getCodeHashName(): string;

    /**
     * Column name holding the generation of the code's set.
     *
     * @return string
     */
    public function getGenerationName(): string;

    /**
     * Column name holding when the code was used.
     *
     * @return string
     */
    public function getUsedAtName(): string;

    /**
     * Column name holding when the code's set was replaced.
     *
     * @return string
     */
    public function getReplacedAtName(): string;

    /**
     * Mark the code used at the given time or now. Does not persist.
     *
     * @param  ?\Carbon\CarbonInterface  $at
     * @return void
     */
    public function markUsed(?CarbonInterface $at = null): void;
}
