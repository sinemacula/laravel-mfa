<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Factors;

use Carbon\CarbonInterface;
use Illuminate\Database\Eloquent\Relations\MorphTo;
use SineMacula\Laravel\Mfa\Contracts\EloquentFactor;
use Tests\Fixtures\Exceptions\UnsupportedFixtureMethodException;

/**
 * Defaults for every `EloquentFactor` persistence method: no-op mutators,
 * conventional column names and a throwing `authenticatable()`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
abstract class AbstractEloquentFactorStub extends AbstractFactorStub implements EloquentFactor
{
    /**
     * Throws, since a stub that is not a model has no relation to give.
     *
     * @return \Illuminate\Database\Eloquent\Relations\MorphTo<\Illuminate\Database\Eloquent\Model, \Illuminate\Database\Eloquent\Model>
     *
     * @throws \Tests\Fixtures\Exceptions\UnsupportedFixtureMethodException
     */
    #[\Override]
    public function authenticatable(): MorphTo
    {
        // The `match` keeps a `return` for CodeSniffer's `InvalidNoReturn`.
        return match (true) {
            default => throw new UnsupportedFixtureMethodException('authenticatable() is unsupported on this stub fixture; override it in the subclass if your test needs it.'),
        };
    }

    /**
     * @return string
     */
    #[\Override]
    public function getTypeName(): string
    {
        return 'type';
    }

    /**
     * @return string
     */
    #[\Override]
    public function getLabelName(): string
    {
        return 'label';
    }

    /**
     * @return string
     */
    #[\Override]
    public function getDestinationName(): string
    {
        return 'destination';
    }

    /**
     * @return string
     */
    #[\Override]
    public function getCredentialReferenceName(): string
    {
        return 'credential_reference';
    }

    /**
     * @return string
     */
    #[\Override]
    public function getTotpAlgorithmName(): string
    {
        return 'totp_algorithm';
    }

    /**
     * @return string
     */
    #[\Override]
    public function getTotpDigitsName(): string
    {
        return 'totp_digits';
    }

    /**
     * @return string
     */
    #[\Override]
    public function getTotpPeriodName(): string
    {
        return 'totp_period';
    }

    /**
     * @return string
     */
    #[\Override]
    public function getLastAcceptedStepName(): string
    {
        return 'last_accepted_step';
    }

    /**
     * No step is ever accepted, since none is kept.
     *
     * @param  int  $step
     * @return bool
     */
    #[\Override]
    public function storeAcceptedStep(int $step): bool
    {
        return false;
    }

    /**
     * @return string
     */
    #[\Override]
    public function getStatusName(): string
    {
        return 'status';
    }

    /**
     * @return string
     */
    #[\Override]
    public function getPreferredName(): string
    {
        return 'preferred';
    }

    /**
     * @return string
     */
    #[\Override]
    public function getConsecutiveFailuresName(): string
    {
        return 'consecutive_failures';
    }

    /**
     * @return string
     */
    #[\Override]
    public function getDisabledAtName(): string
    {
        return 'disabled_at';
    }

    /**
     * @return ?\Carbon\CarbonInterface
     */
    #[\Override]
    public function getLockedUntil(): ?CarbonInterface
    {
        return null;
    }

    /**
     * @return string
     */
    #[\Override]
    public function getLockedUntilName(): string
    {
        return 'locked_until';
    }

    /**
     * @return string
     */
    #[\Override]
    public function getApplicationName(): string
    {
        return 'application';
    }

    /**
     * @return string
     */
    #[\Override]
    public function getConfirmedAtName(): string
    {
        return 'confirmed_at';
    }

    /**
     * @return string
     */
    #[\Override]
    public function getLastUsedAtName(): string
    {
        return 'last_used_at';
    }

    /**
     * @return string
     */
    #[\Override]
    public function getSecretName(): string
    {
        return 'secret';
    }

    /**
     * @param  ?\Carbon\CarbonInterface  $at
     * @return void
     */
    #[\Override]
    public function recordVerification(?CarbonInterface $at = null): void
    {
        // Not tracked.
    }

    /**
     * @param  ?\Carbon\CarbonInterface  $at
     * @return void
     */
    #[\Override]
    public function confirm(?CarbonInterface $at = null): void
    {
        // Not tracked.
    }

    /**
     * @return void
     */
    #[\Override]
    public function persist(): void
    {
        // Not tracked.
    }
}
