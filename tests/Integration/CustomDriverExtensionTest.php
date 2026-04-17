<?php

declare(strict_types = 1);

namespace Tests\Integration;

use SineMacula\Laravel\Mfa\Contracts\Factor;
use SineMacula\Laravel\Mfa\Contracts\FactorDriver;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use Tests\Fixtures\MyDriverFactor;
use Tests\Fixtures\RecordingFactorDriver;
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
     * Test a custom driver registered via Mfa::extend resolves to the
     * registered instance.
     *
     * @return void
     */
    public function testCustomDriverResolvesToRegisteredInstance(): void
    {
        $driver = new RecordingFactorDriver;

        Mfa::extend('my_driver', static fn () => $driver);

        self::assertSame($driver, Mfa::driver('my_driver'));
    }

    /**
     * Test invoking a custom driver's verify increments its call counter.
     *
     * @return void
     */
    public function testCustomDriverVerifyCallReachesRegisteredInstance(): void
    {
        $driver = new RecordingFactorDriver;

        Mfa::extend('my_driver', static fn () => $driver);

        Mfa::driver('my_driver')->verify(new MyDriverFactor, 'correct');

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
