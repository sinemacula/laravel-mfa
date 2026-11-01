<?php

declare(strict_types = 1);

namespace Tests\Unit\Drivers;

use Illuminate\Config\Repository;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Drivers\TotpSettings;

/**
 * Unit tests for `TotpSettings`: each setting's default, the bounds it accepts,
 * and the message a value past them fails with.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(TotpSettings::class)]
final class TotpSettingsTest extends TestCase
{
    /**
     * Rows of `[key, reader, default, least, greatest]`.
     *
     * @return iterable<string, array{string, \Closure(\SineMacula\Laravel\Mfa\Drivers\TotpSettings): int, int, int, int}>
     */
    public static function settings(): iterable
    {
        yield 'digits' => ['digits', static fn (TotpSettings $settings): int => $settings->digits(), 6, 6, 8];
        yield 'period' => ['period', static fn (TotpSettings $settings): int => $settings->period(), 30, 15, 120];
        yield 'window' => ['window', static fn (TotpSettings $settings): int => $settings->window(), 1, 0, 3];
    }

    /**
     * Each setting takes its default (within its bounds) when unset, reads
     * either bound as an integer or the digit string `env()` returns, and
     * refuses a value past either bound, or one that is not an integer, naming
     * the key and its bounds, both as it is read and when every setting is
     * validated.
     *
     * @param  string  $key
     * @param  \Closure(\SineMacula\Laravel\Mfa\Drivers\TotpSettings): int  $read
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

        $message = sprintf('mfa.totp.%s must be an integer from %d to %d.', $key, $least, $most);

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
     * The algorithm defaults to `sha1`, reads each RFC 6238 algorithm, and
     * refuses any other value naming the key, as it is read and when every
     * setting is validated.
     *
     * @return void
     */
    public function testTheAlgorithmIsOneOfTheRfcAlgorithms(): void
    {
        self::assertSame('sha1', self::settingsWith([])->algorithm());

        foreach (['sha1', 'sha256', 'sha512'] as $algorithm) {
            self::assertSame($algorithm, self::settingsWith(['algorithm' => $algorithm])->algorithm());
        }

        foreach (['md5', 'SHA1', null, 1] as $value) {

            $settings = self::settingsWith(['algorithm' => $value]);

            foreach ([static fn (): string => $settings->algorithm(), static fn () => $settings->validate()] as $call) {

                try {
                    $call();
                    self::fail(sprintf('Expected %s to be refused.', var_export($value, true)));
                } catch (\InvalidArgumentException $exception) {
                    self::assertSame('mfa.totp.algorithm must be one of sha1, sha256, sha512.', $exception->getMessage());
                }
            }
        }
    }

    /**
     * The parameters of a new enrolment are the configured algorithm, digits
     * and period, and fail closed on a value out of bounds.
     *
     * @return void
     */
    public function testTheParametersOfANewEnrollmentAreTheConfiguredOnes(): void
    {
        $defaults = self::settingsWith([])->parameters();

        self::assertSame(['sha1', 6, 30], [$defaults->algorithm, $defaults->digits, $defaults->period]);

        $configured = self::settingsWith(['algorithm' => 'sha512', 'digits' => '8', 'period' => 60])->parameters();

        self::assertSame(['sha512', 8, 60], [$configured->algorithm, $configured->digits, $configured->period]);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('mfa.totp.period must be an integer from 15 to 120.');

        self::settingsWith(['period' => 121])->parameters();
    }

    /**
     * Build the settings over an `mfa.totp` block.
     *
     * @param  array<string, mixed>  $block
     * @return \SineMacula\Laravel\Mfa\Drivers\TotpSettings
     */
    private static function settingsWith(array $block): TotpSettings
    {
        return new TotpSettings(new Repository(['mfa' => ['totp' => $block]]));
    }
}
