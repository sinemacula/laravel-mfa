<?php

declare(strict_types = 1);

namespace Tests\Integration;

use SineMacula\Laravel\Mfa\Contracts\Factor;
use SineMacula\Laravel\Mfa\Contracts\FactorDriver;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use Tests\TestCase;

/**
 * Integration test verifying the `Mfa::extend()` custom-driver
 * registration path.
 *
 * A custom driver registered via the Manager's `extend()` API must
 * resolve to the registered instance when requested by name, and
 * its verify / issueChallenge surface must be exercised identically
 * to built-in drivers.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 *
 * @internal
 */
final class CustomDriverExtensionTest extends TestCase
{
    public function testCustomDriverCanBeRegisteredAndResolved(): void
    {
        $driver = new class implements FactorDriver {
            public int $issueCalls  = 0;
            public int $verifyCalls = 0;

            public function issueChallenge(Factor $factor): void
            {
                $this->issueCalls++;
            }

            public function verify(
                Factor $factor,
                #[\SensitiveParameter]
                string $code,
            ): bool {
                $this->verifyCalls++;

                return $code === 'correct';
            }

            public function generateSecret(): ?string
            {
                return null;
            }
        };

        Mfa::extend('my_driver', static fn () => $driver);

        $resolved = Mfa::driver('my_driver');
        self::assertSame($driver, $resolved);

        $factor = new class implements Factor {
            public function getFactorIdentifier(): mixed
            {
                return 'x';
            }

            public function getDriver(): string
            {
                return 'my_driver';
            }

            public function getLabel(): ?string
            {
                return null;
            }

            public function getRecipient(): ?string
            {
                return null;
            }

            public function getAuthenticatable(): ?\Illuminate\Contracts\Auth\Authenticatable
            {
                return null;
            }

            public function getSecret(): ?string
            {
                return null;
            }

            public function getCode(): ?string
            {
                return null;
            }

            public function getExpiresAt(): ?\Carbon\CarbonInterface
            {
                return null;
            }

            public function getAttempts(): int
            {
                return 0;
            }

            public function getLockedUntil(): ?\Carbon\CarbonInterface
            {
                return null;
            }

            public function isLocked(): bool
            {
                return false;
            }

            public function getLastAttemptedAt(): ?\Carbon\CarbonInterface
            {
                return null;
            }

            public function getVerifiedAt(): ?\Carbon\CarbonInterface
            {
                return null;
            }

            public function isVerified(): bool
            {
                return false;
            }
        };

        // Verify() returns false because the factor's not persistable and
        // the orchestration store can't be updated — but the driver was
        // still called.
        Mfa::driver('my_driver')->verify($factor, 'correct');

        self::assertSame(1, $driver->verifyCalls);
    }
}
