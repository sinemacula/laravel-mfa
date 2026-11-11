<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Concerns;

use Carbon\Carbon;
use Carbon\CarbonInterface;
use Illuminate\Database\Eloquent\Relations\MorphTo;

/**
 * `RecoveryCode` for an Eloquent model; override a `get*Name()` method to remap
 * its column.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
trait ActsAsRecoveryCode
{
    /**
     * @formatter:off
     *
     * @return \Illuminate\Database\Eloquent\Relations\MorphTo<\Illuminate\Database\Eloquent\Model, \Illuminate\Database\Eloquent\Model>
     *
     * @formatter:on
     */
    public function authenticatable(): MorphTo
    {
        // The contract widens morphTo()'s `MorphTo<Model, $this>` bound.
        // @phpstan-ignore return.type
        return $this->morphTo();
    }

    /**
     * @return ?string
     */
    public function getCodeHash(): ?string
    {
        /** @var mixed $value */
        $value = $this->getAttribute($this->getCodeHashName());

        return is_string($value) ? $value : null;
    }

    /**
     * @return string
     */
    public function getCodeHashName(): string
    {
        return 'code_hash';
    }

    /**
     * @return string
     */
    public function getGenerationName(): string
    {
        return 'generation';
    }

    /**
     * @return ?\Carbon\CarbonInterface
     */
    public function getUsedAt(): ?CarbonInterface
    {
        /** @var mixed $value */
        $value = $this->getAttribute($this->getUsedAtName());

        return $value instanceof CarbonInterface ? $value : null;
    }

    /**
     * @return string
     */
    public function getUsedAtName(): string
    {
        return 'used_at';
    }

    /**
     * When a newer set replaced the code's set.
     *
     * @return ?\Carbon\CarbonInterface
     */
    public function getReplacedAt(): ?CarbonInterface
    {
        /** @var mixed $value */
        $value = $this->getAttribute($this->getReplacedAtName());

        return $value instanceof CarbonInterface ? $value : null;
    }

    /**
     * @return string
     */
    public function getReplacedAtName(): string
    {
        return 'replaced_at';
    }

    /**
     * @return bool
     */
    public function isUsable(): bool
    {
        return $this->getUsedAt() === null && $this->getReplacedAt() === null;
    }

    /**
     * @param  ?\Carbon\CarbonInterface  $at
     * @return void
     */
    public function markUsed(?CarbonInterface $at = null): void
    {
        $this->setAttribute($this->getUsedAtName(), $at ?? Carbon::now());
    }
}
