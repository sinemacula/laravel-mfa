<?php

declare(strict_types = 1);

namespace Tests\Unit\Codes;

use Illuminate\Config\Repository;
use Illuminate\Mail\Mailable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Codes\CodeSettings;
use SineMacula\Laravel\Mfa\Codes\MfaCodeMessage;
use Tests\Fixtures\Codes\CustomMfaCodeMessage;

/**
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CodeSettings::class)]
final class CodeSettingsTest extends TestCase
{
    /**
     * Rows of `[key, reader, default, least, greatest]`.
     *
     * @return iterable<string, array{string, \Closure(\SineMacula\Laravel\Mfa\Codes\CodeSettings): int, int, int, int}>
     */
    public static function settings(): iterable
    {
        yield 'length' => ['length', static fn (CodeSettings $settings): int => $settings->length(), 6, 6, 10];
        yield 'ttl_minutes' => ['ttl_minutes', static fn (CodeSettings $settings): int => $settings->ttlMinutes(), 10, 1, 10];
        yield 'max_attempts' => ['max_attempts', static fn (CodeSettings $settings): int => $settings->maxAttempts(), 5, 1, 10];
        yield 'factor_send_limit' => ['factor_send_limit', static fn (CodeSettings $settings): int => $settings->factorSendLimit(), 5, 1, 50];
        yield 'identity_send_limit' => ['identity_send_limit', static fn (CodeSettings $settings): int => $settings->identitySendLimit(), 10, 1, 100];
        yield 'send_window_minutes' => ['send_window_minutes', static fn (CodeSettings $settings): int => $settings->sendWindowMinutes(), 60, 1, 1440];
    }

    /**
     * Bounds read as an integer or an `env()` digit string; anything past them
     * is refused on read and on validation.
     *
     * @param  string  $key
     * @param  \Closure(\SineMacula\Laravel\Mfa\Codes\CodeSettings): int  $read
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

        $message = sprintf('mfa.codes.%s must be an integer from %d to %d.', $key, $least, $most);

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
     * @return void
     */
    public function testTheDefaultsValidate(): void
    {
        $this->expectNotToPerformAssertions();

        self::settingsWith([])->validate();
    }

    /**
     * Defaults to 60 seconds and reaches from 0 to the code lifetime.
     *
     * @return void
     */
    public function testTheResendCooldownIsBoundedByTheCodeLifetime(): void
    {
        self::assertSame(60, self::settingsWith([])->resendCooldownSeconds());
        self::assertSame(0, self::settingsWith(['resend_cooldown_seconds' => 0])->resendCooldownSeconds());
        self::assertSame(600, self::settingsWith(['resend_cooldown_seconds' => '600'])->resendCooldownSeconds());
        self::assertSame(120, self::settingsWith(['ttl_minutes' => 2, 'resend_cooldown_seconds' => 120])->resendCooldownSeconds());

        self::assertRefused(
            [-1, 601, 'soon'],
            'resend_cooldown_seconds',
            static fn (CodeSettings $settings): int => $settings->resendCooldownSeconds(),
            'mfa.codes.resend_cooldown_seconds must be an integer from 0 to 600.',
        );

        $shorter = self::settingsWith(['ttl_minutes' => 2, 'resend_cooldown_seconds' => 121]);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('mfa.codes.resend_cooldown_seconds must be an integer from 0 to 120.');

        $shorter->resendCooldownSeconds();
    }

    /**
     * Defaults to 30 minutes and reaches from the code lifetime to 60 minutes.
     *
     * @return void
     */
    public function testTheChallengeLifetimeIsBoundedByTheCodeLifetime(): void
    {
        self::assertSame(30, self::settingsWith([])->challengeTtlMinutes());
        self::assertSame(10, self::settingsWith(['challenge_ttl_minutes' => 10])->challengeTtlMinutes());
        self::assertSame(60, self::settingsWith(['challenge_ttl_minutes' => '60'])->challengeTtlMinutes());
        self::assertSame(2, self::settingsWith(['ttl_minutes' => 2, 'challenge_ttl_minutes' => 2])->challengeTtlMinutes());

        self::assertRefused(
            [9, 61, 'later'],
            'challenge_ttl_minutes',
            static fn (CodeSettings $settings): int => $settings->challengeTtlMinutes(),
            'mfa.codes.challenge_ttl_minutes must be an integer from 10 to 60.',
        );

        $shorter = self::settingsWith(['ttl_minutes' => 5, 'challenge_ttl_minutes' => 4]);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('mfa.codes.challenge_ttl_minutes must be an integer from 5 to 60.');

        $shorter->challengeTtlMinutes();
    }

    /**
     * Defaults to `MfaCodeMessage`, reads a subclass, and refuses any other
     * class or value.
     *
     * @return void
     */
    public function testTheMailableIsTheCodeMessageOrASubclass(): void
    {
        self::assertSame(MfaCodeMessage::class, self::settingsWith([])->mailable());
        self::assertSame(CustomMfaCodeMessage::class, self::settingsWith(['mailable' => CustomMfaCodeMessage::class])->mailable());

        self::assertRefused(
            [Mailable::class, 'Missing\Mailable', null],
            'mailable',
            static fn (CodeSettings $settings): string => $settings->mailable(),
            sprintf('mfa.codes.mailable must name %s or a subclass of it.', MfaCodeMessage::class),
        );
    }

    /**
     * Each value is refused with the message, on read and on validation.
     *
     * @param  list<mixed>  $values
     * @param  string  $key
     * @param  \Closure(\SineMacula\Laravel\Mfa\Codes\CodeSettings): mixed  $read
     * @param  string  $message
     * @return void
     */
    private static function assertRefused(array $values, string $key, \Closure $read, string $message): void
    {
        foreach ($values as $value) {

            $settings = self::settingsWith([$key => $value]);

            foreach ([static fn (): mixed => $read($settings), static fn () => $settings->validate()] as $call) {

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
     * @param  array<string, mixed>  $block
     * @return \SineMacula\Laravel\Mfa\Codes\CodeSettings
     */
    private static function settingsWith(array $block): CodeSettings
    {
        return new CodeSettings(new Repository(['mfa' => ['codes' => $block]]));
    }
}
