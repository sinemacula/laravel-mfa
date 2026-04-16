<?php

declare(strict_types = 1);

namespace Tests\Unit\Drivers;

use Carbon\CarbonInterface;
use Illuminate\Contracts\Auth\Authenticatable;
use PragmaRX\Google2FA\Google2FA;
use SineMacula\Laravel\Mfa\Contracts\Factor;
use SineMacula\Laravel\Mfa\Drivers\TotpDriver;
use Tests\TestCase;

/**
 * Unit tests for `TotpDriver`.
 *
 * Exercises the Google2FA-backed verification path, secret
 * generation, and the implicit-challenge (no-op) contract for the
 * TOTP driver.
 *
 * The missing-dependency constructor branch (`Google2FA` class
 * absent) is not exercised here — `pragmarx/google2fa` is installed
 * as a `require-dev` dependency, making it impossible to simulate the
 * absent-class condition from inside the autoloaded test process.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 *
 * @internal
 */
final class TotpDriverTest extends TestCase
{
    public function testIssueChallengeIsNoOp(): void
    {
        $driver = new TotpDriver;
        $factor = $this->makeFactor(secret: 'IGNORED');

        // No return value, no state mutation, no exception — the TOTP
        // challenge is generated client-side.
        $driver->issueChallenge($factor);

        self::assertSame('IGNORED', $factor->getSecret());
    }

    public function testVerifyReturnsFalseWhenSecretIsNull(): void
    {
        $driver = new TotpDriver;
        $factor = $this->makeFactor(secret: null);

        self::assertFalse($driver->verify($factor, '123456'));
    }

    public function testVerifyReturnsFalseWhenSecretIsEmptyString(): void
    {
        $driver = new TotpDriver;
        $factor = $this->makeFactor(secret: '');

        self::assertFalse($driver->verify($factor, '123456'));
    }

    public function testVerifyReturnsTrueForCurrentTotpCode(): void
    {
        $google2fa = new Google2FA;
        $secret    = $google2fa->generateSecretKey();
        $code      = $google2fa->getCurrentOtp($secret);

        $driver = new TotpDriver;
        $factor = $this->makeFactor(secret: $secret);

        self::assertTrue($driver->verify($factor, $code));
    }

    public function testVerifyReturnsFalseForWrongCode(): void
    {
        $google2fa = new Google2FA;
        $secret    = $google2fa->generateSecretKey();

        $driver = new TotpDriver;
        $factor = $this->makeFactor(secret: $secret);

        // '000000' is astronomically unlikely to be the current TOTP
        // for a freshly generated secret — the Google2FA algorithm
        // draws from 10^6 candidates across the active window.
        self::assertFalse($driver->verify($factor, '000000'));
    }

    public function testGenerateSecretReturnsNonEmptyBase32String(): void
    {
        $driver = new TotpDriver;
        $secret = $driver->generateSecret();

        self::assertIsString($secret);
        self::assertNotSame('', $secret);
        self::assertMatchesRegularExpression('/^[A-Z2-7]+$/', $secret);
    }

    /**
     * Build an in-memory `Factor` stub exposing the given stored
     * secret so the verify branches can be exercised without hitting
     * the database.
     *
     * @param  ?string  $secret
     */
    private function makeFactor(?string $secret): Factor
    {
        return new class ($secret) implements Factor {
            public function __construct(
                private readonly ?string $secret,
            ) {}

            public function getFactorIdentifier(): mixed
            {
                return 'totp-stub';
            }

            public function getDriver(): string
            {
                return 'totp';
            }

            public function getLabel(): ?string
            {
                return null;
            }

            public function getRecipient(): ?string
            {
                return null;
            }

            public function getAuthenticatable(): ?Authenticatable
            {
                return null;
            }

            public function getSecret(): ?string
            {
                return $this->secret;
            }

            public function getCode(): ?string
            {
                return null;
            }

            public function getExpiresAt(): ?CarbonInterface
            {
                return null;
            }

            public function getAttempts(): int
            {
                return 0;
            }

            public function getLockedUntil(): ?CarbonInterface
            {
                return null;
            }

            public function isLocked(): bool
            {
                return false;
            }

            public function getLastAttemptedAt(): ?CarbonInterface
            {
                return null;
            }

            public function getVerifiedAt(): ?CarbonInterface
            {
                return null;
            }

            public function isVerified(): bool
            {
                return false;
            }
        };
    }
}
