<?php

declare(strict_types = 1);

namespace Tests\Unit\Attempts;

use Carbon\Carbon;
use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Mfa\Attempts\AttemptKeys;
use SineMacula\Laravel\Mfa\Attempts\AttemptSettings;
use SineMacula\Laravel\Mfa\Attempts\AttemptStore;
use SineMacula\Laravel\Mfa\Attempts\IpThrottle;
use SineMacula\Laravel\Mfa\Attempts\Lockout;
use SineMacula\Laravel\Mfa\Enums\AttemptScope;
use Tests\TestCase;

/**
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(IpThrottle::class)]
final class IpThrottleTest extends TestCase
{
    /** @var string The address the attempts are made from. */
    private const string IP = '192.0.2.1';

    /**
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        Carbon::setTestNow('2026-11-01 12:00:00');
    }

    /**
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Carbon::setTestNow();

        parent::tearDown();
    }

    /**
     * @return iterable<string, array{?string}>
     */
    public static function missingAddresses(): iterable
    {
        yield 'no address' => [null];
        yield 'an empty address' => [''];
    }

    /**
     * It takes no slot.
     *
     * @param  ?string  $ip
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     */
    #[DataProvider('missingAddresses')]
    public function testAnAttemptWithoutAnAddressIsNotThrottled(?string $ip): void
    {
        config()->set('mfa.attempts.ip_limit', 1);

        $this->hold(1);

        self::assertNull($this->throttle()->take($ip, $this->settings()));
        self::assertNull($this->throttle()->lockout($ip, $this->settings(), CarbonImmutable::now()));
        self::assertSame(1, $this->hits());
    }

    /**
     * It ends a window's length from now, and is answered with its key and the
     * window it came from.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     */
    public function testASlotIsTakenFromTheWindow(): void
    {
        config()->set('mfa.attempts.window_seconds', 60);

        $slot = $this->throttle()->take(self::IP, $this->settings());

        self::assertIsArray($slot);
        self::assertSame($this->key(), $slot[0]);
        self::assertSame(['hits' => 1, 'ends' => CarbonImmutable::now()->addMinute()->getTimestamp()], $this->store()->read([$this->key()])[$this->key()]);
    }

    /**
     * The throttle ends with the window, and nothing is counted.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     */
    public function testAFullWindowRefusesTheSlot(): void
    {
        config()->set('mfa.attempts.ip_limit', 2);
        config()->set('mfa.attempts.window_seconds', 60);

        $this->throttle()->take(self::IP, $this->settings());
        $this->throttle()->take(self::IP, $this->settings());

        $lockout = $this->throttle()->take(self::IP, $this->settings());

        self::assertInstanceOf(Lockout::class, $lockout);
        self::assertSame(AttemptScope::IP, $lockout->scope);
        self::assertEquals(CarbonImmutable::now()->addMinute(), $lockout->until);
        self::assertSame(2, $this->hits());
    }

    /**
     * Giving back no slot changes nothing.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     */
    public function testASlotIsGivenBack(): void
    {
        $this->throttle()->take(self::IP, $this->settings());

        $slot = $this->throttle()->take(self::IP, $this->settings());

        self::assertIsArray($slot);

        $this->throttle()->giveBack(null);

        self::assertSame(2, $this->hits());

        $this->throttle()->giveBack($slot);

        self::assertSame(1, $this->hits());
    }

    /**
     * Until the window ends.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     */
    public function testAFullLiveWindowThrottlesTheAddress(): void
    {
        config()->set('mfa.attempts.ip_limit', 2);

        $ends = CarbonImmutable::now()->addMinute();

        $this->hold(2, $ends);

        $lockout = $this->throttle()->lockout(self::IP, $this->settings(), CarbonImmutable::now());

        self::assertSame(AttemptScope::IP, $lockout?->scope);
        self::assertEquals($ends, $lockout->until);
        self::assertNull($this->throttle()->lockout(self::IP, $this->settings(), $ends));
        self::assertNull($this->throttle()->lockout('198.51.100.7', $this->settings(), CarbonImmutable::now()));
    }

    /**
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     */
    public function testAWindowBelowTheLimitDoesNotThrottle(): void
    {
        config()->set('mfa.attempts.ip_limit', 2);

        $this->hold(1);

        self::assertNull($this->throttle()->lockout(self::IP, $this->settings(), CarbonImmutable::now()));
    }

    /**
     * The window ends a minute from now by default.
     *
     * @param  int  $hits
     * @param  ?\Carbon\CarbonImmutable  $ends
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     */
    private function hold(int $hits, ?CarbonImmutable $ends = null): void
    {
        $ends ??= CarbonImmutable::now()->addMinute();

        DB::table('mfa_attempts')->insert([
            'key'            => $this->key(),
            'scope'          => AttemptScope::IP->value,
            'hits'           => $hits,
            'window_ends_at' => $ends->format('Y-m-d H:i:s'),
        ]);
    }

    /**
     * @return int
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     */
    private function hits(): int
    {
        return $this->store()->read([$this->key()])[$this->key()]['hits'] ?? 0;
    }

    /**
     * @return string
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     */
    private function key(): string
    {
        return $this->container()->make(AttemptKeys::class)->ip(self::IP);
    }

    /**
     * @return \SineMacula\Laravel\Mfa\Attempts\AttemptSettings
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function settings(): AttemptSettings
    {
        return $this->container()->make(AttemptSettings::class);
    }

    /**
     * @return \SineMacula\Laravel\Mfa\Attempts\AttemptStore
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function store(): AttemptStore
    {
        return $this->container()->make(AttemptStore::class);
    }

    /**
     * @return \SineMacula\Laravel\Mfa\Attempts\IpThrottle
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function throttle(): IpThrottle
    {
        return $this->container()->make(IpThrottle::class);
    }
}
