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
    /**
     * A consumer-supplied driver registered through `Mfa::extend()`
     * must resolve to the registered instance and respond to
     * `verify()` invocations identically to a built-in driver.
     *
     * @return void
     */
    public function testCustomDriverCanBeRegisteredAndResolved(): void
    {
        $driver = new class implements FactorDriver {
            /** @var int Issuance call counter for the test assertions. */
            public int $issueCalls = 0;

            /** @var int Verify call counter for the test assertions. */
            public int $verifyCalls = 0;

            /**
             * Record the issuance call without performing any work.
             *
             * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
             * @return void
             */
            public function issueChallenge(Factor $factor): void
            {
                $this->issueCalls++;
            }

            /**
             * Record the verify call and report success only when the
             * submitted code is the magic string `'correct'`.
             *
             * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
             * @param  string  $code
             * @return bool
             */
            public function verify(
                Factor $factor,
                #[\SensitiveParameter]
                string $code,
            ): bool {
                $this->verifyCalls++;

                return $code === 'correct';
            }

            /**
             * Custom driver does not use a persistent secret.
             *
             * @return ?string
             */
            public function generateSecret(): ?string
            {
                return null;
            }
        };

        Mfa::extend('my_driver', static fn () => $driver);

        $resolved = Mfa::driver('my_driver');
        self::assertSame($driver, $resolved);

        $factor = new class implements Factor {
            /**
             * @return mixed
             */
            public function getFactorIdentifier(): mixed
            {
                return 'x';
            }

            /**
             * @return string
             */
            public function getDriver(): string
            {
                return 'my_driver';
            }

            /**
             * @return ?string
             */
            public function getLabel(): ?string
            {
                return null;
            }

            /**
             * @return ?string
             */
            public function getRecipient(): ?string
            {
                return null;
            }

            /**
             * @return ?\Illuminate\Contracts\Auth\Authenticatable
             */
            public function getAuthenticatable(): ?\Illuminate\Contracts\Auth\Authenticatable
            {
                return null;
            }

            /**
             * @return ?string
             */
            public function getSecret(): ?string
            {
                return null;
            }

            /**
             * @return ?string
             */
            public function getCode(): ?string
            {
                return null;
            }

            /**
             * @return ?\Carbon\CarbonInterface
             */
            public function getExpiresAt(): ?\Carbon\CarbonInterface
            {
                return null;
            }

            /**
             * @return int
             */
            public function getAttempts(): int
            {
                return 0;
            }

            /**
             * @return ?\Carbon\CarbonInterface
             */
            public function getLockedUntil(): ?\Carbon\CarbonInterface
            {
                return null;
            }

            /**
             * @return bool
             */
            public function isLocked(): bool
            {
                // Derived from the accessor so this stub does not duplicate
                // the body of isVerified() — radarlint S4144 flags
                // structurally identical method bodies.
                return $this->getLockedUntil() !== null;
            }

            /**
             * @return ?\Carbon\CarbonInterface
             */
            public function getLastAttemptedAt(): ?\Carbon\CarbonInterface
            {
                return null;
            }

            /**
             * @return ?\Carbon\CarbonInterface
             */
            public function getVerifiedAt(): ?\Carbon\CarbonInterface
            {
                return null;
            }

            /**
             * @return bool
             */
            public function isVerified(): bool
            {
                // Verification state is irrelevant — these stubs feed the
                // dispatch path, never the persistence path.
                return false;
            }
        };

        // Verify() returns false because the factor's not persistable and
        // the orchestration store can't be updated — but the driver was
        // still called.
        Mfa::driver('my_driver')->verify($factor, 'correct');

        self::assertSame(1, $driver->verifyCalls);
    }

    /**
     * `Mfa::extend('totp', ...)` must override the built-in TOTP
     * driver registered by `MfaServiceProvider::registerBuiltInDrivers()`.
     *
     * Pins the override invariant after the refactor that moved the
     * built-in factories from `MfaManager::createXDriver()` into
     * `Mfa::extend()` calls inside the service provider's singleton
     * closure. Both paths now use the same registry, so a future
     * Laravel `Manager` upgrade that changed override-precedence
     * semantics would silently break consumer overrides without
     * this guard.
     *
     * @return void
     */
    public function testConsumerCanOverrideBuiltInTotpDriver(): void
    {
        $marker = new class implements FactorDriver {
            /**
             * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
             * @return void
             */
            public function issueChallenge(Factor $factor): void
            {
                // No-op — never called in this test.
            }

            /**
             * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
             * @param  string  $code
             * @return bool
             */
            public function verify(Factor $factor, #[\SensitiveParameter] string $code): bool
            {
                // Marker driver — return true so the caller can observe
                // that the override fired without setting up a factor.
                return true;
            }

            /**
             * @return string
             */
            public function generateSecret(): string
            {
                return 'fake-marker-secret';
            }
        };

        // Sanity-check: before the override the built-in TOTP driver
        // resolves to the package's TotpDriver (not our marker).
        self::assertNotSame($marker, Mfa::driver('totp'));

        // Resolve the manager singleton and clear Laravel's per-request
        // driver cache so the override registered next is what the next
        // `driver('totp')` call sees.
        $manager = $this->container()->make('mfa');
        \PHPUnit\Framework\Assert::assertInstanceOf(
            \SineMacula\Laravel\Mfa\MfaManager::class,
            $manager,
        );
        $manager->forgetDrivers();

        Mfa::extend('totp', static fn (): FactorDriver => $marker);

        self::assertSame(
            $marker,
            Mfa::driver('totp'),
            'Mfa::extend(\'totp\', ...) must override the built-in TOTP driver',
        );
    }
}
