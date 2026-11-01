<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Factors;

use Carbon\CarbonInterface;
use Illuminate\Database\Eloquent\Relations\MorphTo;
use SineMacula\Laravel\Mfa\Contracts\EloquentFactor;
use Tests\Fixtures\Exceptions\UnsupportedFixtureMethodException;

/**
 * Default implementation of the `EloquentFactor` contract for test stubs.
 * Extends `AbstractFactorStub` (which covers the parent `Factor` surface) and
 * adds safe defaults for every persistence method — no-op mutators,
 * conventional column-name strings, and a loud-throwing `authenticatable()`
 * that surfaces accidental future callers rather than returning a half-built
 * relation.
 *
 * Test fixtures override only the methods relevant to the scenario they
 * exercise. Keeps each anonymous subclass well below the project's
 * max-methods-per-class threshold without resorting to `@SuppressWarnings`
 * annotations.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
abstract class AbstractEloquentFactorStub extends AbstractFactorStub implements EloquentFactor
{
    /**
     * Polymorphic relation accessor — required by the contract but almost never
     * exercised on a non-Model fixture. Throws so an accidental future caller
     * fails loudly rather than receiving a half-built relation.
     *
     * @return \Illuminate\Database\Eloquent\Relations\MorphTo<\Illuminate\Database\Eloquent\Model, \Illuminate\Database\Eloquent\Model>
     *
     * @throws \Tests\Fixtures\Exceptions\UnsupportedFixtureMethodException
     */
    #[\Override]
    public function authenticatable(): MorphTo
    {
        // Wrapping the throw in a `match` keeps the `return` syntactically
        // present so CodeSniffer's `InvalidNoReturn` does not flag the @return
        // tag, even though the function is logically `never`-returning.
        return match (true) {
            default => throw new UnsupportedFixtureMethodException('authenticatable() is unsupported on this stub fixture; override it in the subclass if your test needs it.'),
        };
    }

    /**
     * Return the conventional type column name.
     *
     * @return string
     */
    #[\Override]
    public function getTypeName(): string
    {
        return 'type';
    }

    /**
     * Return the conventional label column name.
     *
     * @return string
     */
    #[\Override]
    public function getLabelName(): string
    {
        return 'label';
    }

    /**
     * Return the conventional destination column name.
     *
     * @return string
     */
    #[\Override]
    public function getDestinationName(): string
    {
        return 'destination';
    }

    /**
     * Return the conventional credential reference column name.
     *
     * @return string
     */
    #[\Override]
    public function getCredentialReferenceName(): string
    {
        return 'credential_reference';
    }

    /**
     * Return the conventional TOTP algorithm column name.
     *
     * @return string
     */
    #[\Override]
    public function getTotpAlgorithmName(): string
    {
        return 'totp_algorithm';
    }

    /**
     * Return the conventional TOTP digits column name.
     *
     * @return string
     */
    #[\Override]
    public function getTotpDigitsName(): string
    {
        return 'totp_digits';
    }

    /**
     * Return the conventional TOTP period column name.
     *
     * @return string
     */
    #[\Override]
    public function getTotpPeriodName(): string
    {
        return 'totp_period';
    }

    /**
     * Return the conventional last accepted step column name.
     *
     * @return string
     */
    #[\Override]
    public function getLastAcceptedStepName(): string
    {
        return 'last_accepted_step';
    }

    /**
     * Return the conventional status column name.
     *
     * @return string
     */
    #[\Override]
    public function getStatusName(): string
    {
        return 'status';
    }

    /**
     * Return the conventional preferred column name.
     *
     * @return string
     */
    #[\Override]
    public function getPreferredName(): string
    {
        return 'preferred';
    }

    /**
     * Return the conventional consecutive failures column name.
     *
     * @return string
     */
    #[\Override]
    public function getConsecutiveFailuresName(): string
    {
        return 'consecutive_failures';
    }

    /**
     * Return the conventional disabled-at column name.
     *
     * @return string
     */
    #[\Override]
    public function getDisabledAtName(): string
    {
        return 'disabled_at';
    }

    /**
     * Return the conventional application column name.
     *
     * @return string
     */
    #[\Override]
    public function getApplicationName(): string
    {
        return 'application';
    }

    /**
     * Return the conventional confirmed-at column name.
     *
     * @return string
     */
    #[\Override]
    public function getConfirmedAtName(): string
    {
        return 'confirmed_at';
    }

    /**
     * Return the conventional last-used-at column name.
     *
     * @return string
     */
    #[\Override]
    public function getLastUsedAtName(): string
    {
        return 'last_used_at';
    }

    /**
     * Return the conventional secret column name.
     *
     * @return string
     */
    #[\Override]
    public function getSecretName(): string
    {
        return 'secret';
    }

    /**
     * Return the conventional code column name.
     *
     * @return string
     */
    #[\Override]
    public function getCodeName(): string
    {
        return 'code';
    }

    /**
     * Return the conventional expires-at column name.
     *
     * @return string
     */
    #[\Override]
    public function getExpiresAtName(): string
    {
        return 'expires_at';
    }

    /**
     * Return the conventional attempts column name.
     *
     * @return string
     */
    #[\Override]
    public function getAttemptsName(): string
    {
        return 'attempts';
    }

    /**
     * Return the conventional locked-until column name.
     *
     * @return string
     */
    #[\Override]
    public function getLockedUntilName(): string
    {
        return 'locked_until';
    }

    /**
     * Return the conventional last-attempted-at column name.
     *
     * @return string
     */
    #[\Override]
    public function getLastAttemptedAtName(): string
    {
        return 'last_attempted_at';
    }

    /**
     * No-op — the fixture does not track attempts.
     *
     * @param  ?\Carbon\CarbonInterface  $at
     * @return void
     */
    #[\Override]
    public function recordAttempt(?CarbonInterface $at = null): void
    {
        // Intentionally empty — see method docblock.
    }

    /**
     * No-op — the fixture does not track attempts.
     *
     * @return void
     */
    #[\Override]
    public function resetAttempts(): void
    {
        // Intentionally empty — see method docblock.
    }

    /**
     * No-op — the fixture does not track lockouts.
     *
     * @param  \Carbon\CarbonInterface  $until
     * @return void
     */
    #[\Override]
    public function applyLockout(CarbonInterface $until): void
    {
        // Intentionally empty — see method docblock.
    }

    /**
     * No-op — the fixture does not track verifications.
     *
     * @param  ?\Carbon\CarbonInterface  $at
     * @return void
     */
    #[\Override]
    public function recordVerification(?CarbonInterface $at = null): void
    {
        // Intentionally empty — see method docblock.
    }

    /**
     * No-op — the fixture does not track confirmation.
     *
     * @param  ?\Carbon\CarbonInterface  $at
     * @return void
     */
    #[\Override]
    public function confirm(?CarbonInterface $at = null): void
    {
        // Intentionally empty — see method docblock.
    }

    /**
     * No-op — the fixture does not track issued codes.
     *
     * @param  string  $code
     * @param  \Carbon\CarbonInterface  $expiresAt
     * @return void
     */
    #[\Override]
    public function issueCode(#[\SensitiveParameter] string $code, CarbonInterface $expiresAt): void
    {
        // Intentionally empty — see method docblock.
    }

    /**
     * No-op — the fixture does not track consumed codes.
     *
     * @return void
     */
    #[\Override]
    public function consumeCode(): void
    {
        // Intentionally empty — see method docblock.
    }

    /**
     * No-op — the fixture does not persist anywhere.
     *
     * @return void
     */
    #[\Override]
    public function persist(): void
    {
        // Intentionally empty — see method docblock.
    }
}
