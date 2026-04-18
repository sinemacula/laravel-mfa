<?php

declare(strict_types = 1);

namespace Tests\Fixtures;

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
 * @copyright   2026 Sine Macula Limited.
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
     * Return the conventional driver column name.
     *
     * @return string
     */
    public function getDriverName(): string
    {
        return 'driver';
    }

    /**
     * Return the conventional label column name.
     *
     * @return string
     */
    public function getLabelName(): string
    {
        return 'label';
    }

    /**
     * Return the conventional recipient column name.
     *
     * @return string
     */
    public function getRecipientName(): string
    {
        return 'recipient';
    }

    /**
     * Return the conventional secret column name.
     *
     * @return string
     */
    public function getSecretName(): string
    {
        return 'secret';
    }

    /**
     * Return the conventional code column name.
     *
     * @return string
     */
    public function getCodeName(): string
    {
        return 'code';
    }

    /**
     * Return the conventional expires-at column name.
     *
     * @return string
     */
    public function getExpiresAtName(): string
    {
        return 'expires_at';
    }

    /**
     * Return the conventional attempts column name.
     *
     * @return string
     */
    public function getAttemptsName(): string
    {
        return 'attempts';
    }

    /**
     * Return the conventional locked-until column name.
     *
     * @return string
     */
    public function getLockedUntilName(): string
    {
        return 'locked_until';
    }

    /**
     * Return the conventional last-attempted-at column name.
     *
     * @return string
     */
    public function getLastAttemptedAtName(): string
    {
        return 'last_attempted_at';
    }

    /**
     * Return the conventional verified-at column name.
     *
     * @return string
     */
    public function getVerifiedAtName(): string
    {
        return 'verified_at';
    }

    /**
     * No-op — the fixture does not track attempts.
     *
     * @param  ?\Carbon\CarbonInterface  $at
     * @return void
     */
    public function recordAttempt(?CarbonInterface $at = null): void
    {
        // Intentionally empty — see method docblock.
    }

    /**
     * No-op — the fixture does not track attempts.
     *
     * @return void
     */
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
    public function recordVerification(?CarbonInterface $at = null): void
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
    public function issueCode(#[\SensitiveParameter] string $code, CarbonInterface $expiresAt): void
    {
        // Intentionally empty — see method docblock.
    }

    /**
     * No-op — the fixture does not track consumed codes.
     *
     * @return void
     */
    public function consumeCode(): void
    {
        // Intentionally empty — see method docblock.
    }

    /**
     * No-op — the fixture does not persist anywhere.
     *
     * @return void
     */
    public function persist(): void
    {
        // Intentionally empty — see method docblock.
    }
}
