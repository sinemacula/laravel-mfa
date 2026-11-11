<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Contracts;

use Carbon\CarbonInterface;
use Illuminate\Database\Eloquent\Relations\MorphTo;

/**
 * One code of an identity's recovery code set, stored as a salted hash and
 * usable until used or replaced by a newer set.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface RecoveryCode
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
     * The salted hash, never the code.
     *
     * @return ?string
     */
    public function getCodeHash(): ?string;

    /**
     * `null` while unused.
     *
     * @return ?\Carbon\CarbonInterface
     */
    public function getUsedAt(): ?CarbonInterface;

    /**
     * When a newer set replaced this one, or `null`.
     *
     * @return ?\Carbon\CarbonInterface
     */
    public function getReplacedAt(): ?CarbonInterface;

    /**
     * Neither used nor replaced.
     *
     * @return bool
     */
    public function isUsable(): bool;

    /**
     * @return string
     */
    public function getCodeHashName(): string;

    /**
     * @return string
     */
    public function getGenerationName(): string;

    /**
     * @return string
     */
    public function getUsedAtName(): string;

    /**
     * @return string
     */
    public function getReplacedAtName(): string;

    /**
     * Mark the code used at the time given, or now, without persisting.
     *
     * @param  ?\Carbon\CarbonInterface  $at
     * @return void
     */
    public function markUsed(?CarbonInterface $at = null): void;
}
