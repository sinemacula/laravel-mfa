<?php

declare(strict_types = 1);

namespace Tests\Integration;

use PHPUnit\Framework\Assert;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Contracts\Factor;
use SineMacula\Laravel\Mfa\Contracts\FactorDriver;
use SineMacula\Laravel\Mfa\Drivers\TotpDriver;
use SineMacula\Laravel\Mfa\Enums\CodeCheck;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\MfaManager;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
use Tests\Fixtures\Drivers\Concerns\DescribesNoChannel;
use Tests\Fixtures\Drivers\NoopFactorDriver;
use Tests\Fixtures\Drivers\RecordingFactorDriver;
use Tests\Fixtures\Factors\MyDriverFactor;
use Tests\Fixtures\Identities\TestUser;
use Tests\TestCase;

/**
 * Integration test verifying the `Mfa::extend()` custom-driver registration
 * path.
 *
 * A custom driver registered via the Manager's `extend()` API must resolve to
 * the registered instance when requested by name, and its `verify()` and
 * `deliver()` surface must be exercised identically to built-in drivers. A
 * consumer's registration of a shipped driver's name wins however it is made:
 * through the facade, a container extender or a resolving callback on `mfa`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(MfaManager::class)]
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

        Mfa::driver('my_driver')->verify(new MyDriverFactor, 'correct', new ProofBinding('user', '1', 'web', 'sign-in-1', Purpose::SIGN_IN));

        self::assertSame(1, $driver->verifyCalls);
    }

    /**
     * `Mfa::extend('totp', ...)` must override the built-in TOTP driver
     * registered by `DriverBindings::extend()`. Pins the override invariant —
     * both built-ins and consumer overrides go through the same `Mfa::extend()`
     * registry, so a future Laravel `Manager` upgrade that changed
     * override-precedence semantics would silently break consumer overrides
     * without this guard. The driver was already resolved once when the
     * override is made, and nothing needs clearing for it to win.
     *
     * @return void
     */
    public function testConsumerCanOverrideBuiltInTotpDriver(): void
    {
        $marker = new class implements FactorDriver {
            use DescribesNoChannel;

            /**
             * Always succeed so the caller can observe that the override fired.
             *
             * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
             * @param  string  $code
             * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
             * @return \SineMacula\Laravel\Mfa\Enums\CodeCheck
             */
            #[\Override]
            public function verify(Factor $factor, #[\SensitiveParameter] string $code, ProofBinding $binding): CodeCheck
            {
                // Marker driver — accept so the caller can observe that the
                // override fired without setting up a factor.
                return CodeCheck::ACCEPTED;
            }
        };

        // Sanity-check: before the override the built-in TOTP driver resolves
        // to the package's TotpDriver (not our marker).
        self::assertNotSame($marker, Mfa::driver('totp'));

        Mfa::extend('totp', static fn (): FactorDriver => $marker);

        self::assertSame(
            $marker,
            Mfa::driver('totp'),
            'Mfa::extend(\'totp\', ...) must override the built-in TOTP driver',
        );
    }

    /**
     * A container extender on `mfa` that registers its own TOTP driver wins
     * over the shipped one, which is registered before extenders run.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testContainerExtenderOverrideOfTotpWins(): void
    {
        $marker = new NoopFactorDriver;

        $this->container()->forgetInstance('mfa');
        $this->container()->extend('mfa', static fn (MfaManager $manager): MfaManager => $manager->extend('totp', fn (): FactorDriver => $marker));

        self::assertSame($marker, $this->manager()->driver('totp'));
    }

    /**
     * A resolving callback on `mfa` that registers its own TOTP driver wins
     * over the shipped one, which is registered before callbacks run.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testResolvingCallbackOverrideOfTotpWins(): void
    {
        $marker = new NoopFactorDriver;

        $this->container()->forgetInstance('mfa');
        $this->container()->resolving('mfa', static function (MfaManager $manager) use ($marker): void {
            $manager->extend('totp', fn (): FactorDriver => $marker);
        });

        self::assertSame($marker, $this->manager()->driver('totp'));
    }

    /**
     * A resolving callback on `mfa` can already use the shipped drivers.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testResolvingCallbackSeesTheShippedDrivers(): void
    {
        $seen = null;

        $this->container()->forgetInstance('mfa');
        $this->container()->resolving('mfa', static function (MfaManager $manager) use (&$seen): void {
            $seen = $manager->driver('totp');
        });

        $this->manager();

        self::assertInstanceOf(TotpDriver::class, $seen);
    }

    /**
     * Resolve the package's MFA manager from the container.
     *
     * @return \SineMacula\Laravel\Mfa\MfaManager
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function manager(): MfaManager
    {
        $manager = $this->container()->make('mfa');

        Assert::assertInstanceOf(MfaManager::class, $manager);

        return $manager;
    }

    /**
     * Create a test user and authenticate as them.
     *
     * @return \Tests\Fixtures\Identities\TestUser
     */
    private function signIn(): TestUser
    {
        /** @var \Tests\Fixtures\Identities\TestUser $user */
        $user = TestUser::query()->create(['email' => 'extension@example.com']);

        $this->actingAs($user);

        return $user;
    }
}
