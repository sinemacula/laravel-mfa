<?php

declare(strict_types = 1);

namespace Tests\Unit\Attempts;

use Illuminate\Config\Repository;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Attempts\AttemptSettings;

/**
 * Unit tests for `AttemptSettings`: each setting's default, the bounds it
 * accepts, and the message a value past them fails with.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AttemptSettings::class)]
final class AttemptSettingsTest extends TestCase
{
    /**
     * Rows of `[key, reader, default, least, greatest]`.
     *
     * @return iterable<string, array{string, \Closure(\SineMacula\Laravel\Mfa\Attempts\AttemptSettings): int, int, int, int}>
     */
    public static function settings(): iterable
    {
        yield 'factor_limit' => ['factor_limit', static fn (AttemptSettings $settings): int => $settings->factorLimit(), 5, 1, 20];
        yield 'identity_limit' => ['identity_limit', static fn (AttemptSettings $settings): int => $settings->identityLimit(), 20, 1, 100];
        yield 'ip_limit' => ['ip_limit', static fn (AttemptSettings $settings): int => $settings->ipLimit(), 100, 1, 10000];
        yield 'window_seconds' => ['window_seconds', static fn (AttemptSettings $settings): int => $settings->windowSeconds(), 900, 60, 86400];
        yield 'lockout_seconds' => ['lockout_seconds', static fn (AttemptSettings $settings): int => $settings->lockoutSeconds(), 900, 60, 86400];
        yield 'failure_ceiling' => ['failure_ceiling', static fn (AttemptSettings $settings): int => $settings->failureCeiling(), 100, 1, 100];
    }

    /**
     * Each setting takes its default (within its bounds) when unset, reads
     * either bound as an integer or the digit string `env()` returns, and
     * refuses a value past either bound, or one that is not an integer, naming
     * the key and its bounds, both as it is read and when every setting is
     * validated.
     *
     * @param  string  $key
     * @param  \Closure(\SineMacula\Laravel\Mfa\Attempts\AttemptSettings): int  $read
     * @param  int  $default
     * @param  int  $least
     * @param  int  $most
     * @return void
     */
    #[DataProvider('settings')]
    public function testEachSettingHasItsDefaultAndBounds(string $key, \Closure $read, int $default, int $least, int $most): void
    {
        self::assertSame($default, $read(self::settingsWith([])));
        self::assertGreaterThanOrEqual($least, $default);
        self::assertLessThanOrEqual($most, $default);
        self::assertSame($least, $read(self::settingsWith([$key => $least])));
        self::assertSame($most, $read(self::settingsWith([$key => (string) $most])));

        $message = sprintf('mfa.attempts.%s must be an integer from %d to %d.', $key, $least, $most);

        foreach ([$least - 1, $most + 1, 'many'] as $value) {

            $settings = self::settingsWith([$key => $value]);

            foreach ([static fn (): int => $read($settings), static fn () => $settings->validate()] as $call) {

                try {
                    $call();
                    self::fail(sprintf('Expected %s to be refused.', var_export($value, true)));
                } catch (\InvalidArgumentException $exception) {
                    self::assertSame($message, $exception->getMessage());
                }
            }
        }
    }

    /**
     * The defaults validate.
     *
     * @return void
     */
    public function testTheDefaultsValidate(): void
    {
        $this->expectNotToPerformAssertions();

        self::settingsWith([])->validate();
    }

    /**
     * Build the settings over an `mfa.attempts` block.
     *
     * @param  array<string, mixed>  $attempts
     * @return \SineMacula\Laravel\Mfa\Attempts\AttemptSettings
     */
    private static function settingsWith(array $attempts): AttemptSettings
    {
        return new AttemptSettings(new Repository(['mfa' => ['attempts' => $attempts]]));
    }
}
