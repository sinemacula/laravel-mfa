<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Concerns;

use Carbon\Carbon;
use Carbon\CarbonInterface;
use Illuminate\Database\Eloquent\Relations\MorphTo;

/**
 * Default implementation of the `RecoveryCode` contract for Eloquent models, so
 * an application's own recovery code model satisfies it by using this trait.
 * Column names are exposed through the `get*Name()` methods, which a model
 * overrides to remap a column.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
trait ActsAsRecoveryCode
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
    public function authenticatable(): MorphTo
    {
        // morphTo() returns `MorphTo<Model, $this>` but the contract requires
        // `MorphTo<Model, Model>`: the bound is widened, not narrowed.
        // @phpstan-ignore return.type
        return $this->morphTo();
    }

    /**
     * Return the code's opaque identifier.
     *
     * @return mixed
     */
    public function getRecoveryCodeIdentifier(): mixed
    {
        return $this->getKey();
    }

    /**
     * Return the salted hash of the code.
     *
     * @return ?string
     */
    public function getCodeHash(): ?string
    {
        /** @var mixed $value */
        $value = $this->getAttribute($this->getCodeHashName());

        return is_string($value) ? $value : null;
    }

    /**
     * Column name holding the code's hash.
     *
     * @return string
     */
    public function getCodeHashName(): string
    {
        return 'code_hash';
    }

    /**
     * Return the generation of the set the code belongs to.
     *
     * @return int
     */
    public function getGeneration(): int
    {
        /** @var mixed $value */
        $value = $this->getAttribute($this->getGenerationName());

        return is_int($value) ? $value : 0;
    }

    /**
     * Column name holding the generation of the code's set.
     *
     * @return string
     */
    public function getGenerationName(): string
    {
        return 'generation';
    }

    /**
     * Return when the code was used.
     *
     * @return ?\Carbon\CarbonInterface
     */
    public function getUsedAt(): ?CarbonInterface
    {
        /** @var mixed $value */
        $value = $this->getAttribute($this->getUsedAtName());

        return $value instanceof CarbonInterface ? $value : null;
    }

    /**
     * Column name holding when the code was used.
     *
     * @return string
     */
    public function getUsedAtName(): string
    {
        return 'used_at';
    }

    /**
     * Return when a newer set replaced the code's set.
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
     * Column name holding when the code's set was replaced.
     *
     * @return string
     */
    public function getReplacedAtName(): string
    {
        return 'replaced_at';
    }

    /**
     * Determine whether the code is neither used nor replaced.
     *
     * @return bool
     */
    public function isUsable(): bool
    {
        return $this->getUsedAt() === null && $this->getReplacedAt() === null;
    }

    /**
     * Mark the code used at the given time or now.
     *
     * @param  ?\Carbon\CarbonInterface  $at
     * @return void
     */
    public function markUsed(?CarbonInterface $at = null): void
    {
        $this->setAttribute($this->getUsedAtName(), $at ?? Carbon::now());
    }

    /**
     * Mark the code replaced by a newer set at the given time or now.
     *
     * @param  ?\Carbon\CarbonInterface  $at
     * @return void
     */
    public function markReplaced(?CarbonInterface $at = null): void
    {
        $this->setAttribute($this->getReplacedAtName(), $at ?? Carbon::now());
    }
}
