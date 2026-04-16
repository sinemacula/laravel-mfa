<?php

declare(strict_types = 1);

namespace Tests\Fixtures;

use Illuminate\Support\Collection;
use SineMacula\Laravel\Mfa\MfaManager;

/**
 * Test double for `MfaManager` used by the `RequireMfa` middleware tests.
 *
 * Extends the real manager so the facade's `@method` assertions line up,
 * but bypasses the container-backed Manager constructor — we only poke
 * the handful of methods the middleware actually invokes.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 *
 * @internal
 */
final class FakeMfaManager extends MfaManager // @phpstan-ignore-line
{
    /** @var bool */
    public bool $shouldUse = true;

    /** @var bool */
    public bool $isSetup = true;

    /** @var bool */
    public bool $hasEverVerified = true;

    /** @var bool */
    public bool $hasExpired = false;

    /** @var ?\Illuminate\Support\Collection<int, \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\Factor> */
    public ?Collection $factors = null;

    /**
     * Intentionally skip parent::__construct to avoid requiring a full
     * container; the middleware only calls the overrides below.
     *
     * @return void
     *
     * @phpstan-ignore constructor.missingParentCall
     */
    public function __construct() {}

    /**
     * Report whether MFA enforcement should fire on this request.
     *
     * @return bool
     */
    public function shouldUse(): bool
    {
        return $this->shouldUse;
    }

    /**
     * Report whether the identity has any factors registered.
     *
     * @return bool
     */
    public function isSetup(): bool
    {
        return $this->isSetup;
    }

    /**
     * Report whether the identity has ever completed a verification.
     *
     * @return bool
     */
    public function hasEverVerified(): bool
    {
        return $this->hasEverVerified;
    }

    /**
     * Report whether the active verification is past its expiry.
     *
     * @param  ?int  $expiresAfter
     * @return bool
     */
    public function hasExpired(?int $expiresAfter = null): bool
    {
        return $this->hasExpired;
    }

    /**
     * Return the seeded collection of factors, or null when unset.
     *
     * @formatter:off
     *
     * @return ?\Illuminate\Support\Collection<int, \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\Factor>
     *
     * @formatter:on
     */
    public function getFactors(): ?Collection
    {
        return $this->factors;
    }
}
