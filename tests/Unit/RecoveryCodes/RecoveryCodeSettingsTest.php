<?php

declare(strict_types = 1);

namespace Tests\Unit\RecoveryCodes;

use Illuminate\Config\Repository;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeSettings;

/**
 * Unit tests for `RecoveryCodeSettings`: each setting's default, the bounds it
 * accepts, and the message a value past them fails with.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RecoveryCodeSettings::class)]
final class RecoveryCodeSettingsTest extends TestCase
{
    /**
     * Rows of `[key, reader, default, least, greatest]`.
     *
     * @return iterable<string, array{string, \Closure(\SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeSettings): int, int, int, int}>
     */
    public static function settings(): iterable
    {
        yield 'count' => ['count', static fn (RecoveryCodeSettings $settings): int => $settings->count(), 10, 1, 50];
        yield 'length' => ['length', static fn (RecoveryCodeSettings $settings): int => $settings->length(), 12, 1, 64];
    }

    /**
     * Each setting takes its default (within its bounds) when unset, reads
     * either bound as an integer or the digit string `env()` returns, and
     * refuses a value past either bound, or one that is not an integer, naming
     * the key and its bounds, both as it is read and when every setting is
     * validated.
     *
     * @param  string  $key
     * @param  \Closure(\SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeSettings): int  $read
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

        $message = sprintf('mfa.recovery_codes.%s must be an integer from %d to %d.', $key, $least, $most);

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
     * The alphabet defaults to digits and capitals without 0, 1, I and O, and
     * reads one of at least two printable ASCII characters, none repeated once
     * case is folded.
     *
     * @return void
     */
    public function testTheAlphabetDefaultsToAnUnambiguousOne(): void
    {
        self::assertSame('23456789ABCDEFGHJKLMNPQRSTUVWXYZ', self::settingsWith([])->alphabet());
        self::assertSame('aB', self::settingsWith(['alphabet' => 'aB'])->alphabet());
        self::assertSame('!~', self::settingsWith(['alphabet' => '!~', 'length' => 40])->alphabet());
    }

    /**
     * An alphabet with fewer than two characters, a character repeated or one
     * that repeats another once case is folded (either would make the draw
     * favour it), a space, a hyphen, a character outside printable ASCII, or a
     * value that is not a string is refused.
     *
     * @return void
     */
    public function testTheAlphabetRefusesWhatNormalizationWouldChange(): void
    {
        self::assertRefused(
            ['', 'A', 'AA', 'aA', 'ABA', 'aAB', str_repeat('A', 63) . 'B', 'AB CD', 'AB-CD', "AB\tCD", "AB\x7F", 'ABÉ', null],
            'alphabet',
            static fn (RecoveryCodeSettings $settings): string => $settings->alphabet(),
            'mfa.recovery_codes.alphabet must be at least two printable ASCII characters, none repeated ignoring case, without spaces or hyphens.',
        );
    }

    /**
     * The low-count threshold defaults to 3, or to the set's size when the set
     * is smaller, and reaches from 0 to the set's size, which bounds it.
     *
     * @return void
     */
    public function testTheLowCountIsBoundedByTheSetSize(): void
    {
        self::assertSame(3, self::settingsWith([])->lowCount());
        self::assertSame(0, self::settingsWith(['low_count' => 0])->lowCount());
        self::assertSame(10, self::settingsWith(['low_count' => '10'])->lowCount());
        self::assertSame(4, self::settingsWith(['count' => 4, 'low_count' => 4])->lowCount());
        self::assertSame(3, self::settingsWith(['count' => 3])->lowCount());
        self::assertSame(2, self::settingsWith(['count' => 2])->lowCount());
        self::assertSame(1, self::settingsWith(['count' => '1'])->lowCount());

        self::settingsWith(['count' => 2, 'length' => 12])->validate();

        self::assertRefused(
            [-1, 11, 'few'],
            'low_count',
            static fn (RecoveryCodeSettings $settings): int => $settings->lowCount(),
            'mfa.recovery_codes.low_count must be an integer from 0 to 10.',
        );
    }

    /**
     * A low-count threshold configured above a smaller set's size is refused,
     * though the default would have followed the set down.
     *
     * @return void
     */
    public function testAConfiguredLowCountAboveASmallerSetIsRefused(): void
    {
        $settings = self::settingsWith(['count' => 2, 'low_count' => 3]);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('mfa.recovery_codes.low_count must be an integer from 0 to 2.');

        $settings->validate();
    }

    /**
     * Entropy is the length times the bits of each character of the alphabet,
     * every one a distinct symbol once case is folded: the default gives 60
     * bits.
     *
     * @return void
     */
    public function testEntropyIsMeasuredAfterNormalization(): void
    {
        self::assertEqualsWithDelta(60.0, self::settingsWith([])->entropyBits(), 0.0001);
        self::assertEqualsWithDelta(16.0, self::settingsWith(['alphabet' => 'abcd', 'length' => 8])->entropyBits(), 0.0001);
        self::assertEqualsWithDelta(8.0, self::settingsWith(['alphabet' => 'aB', 'length' => 8])->entropyBits(), 0.0001);
    }

    /**
     * A length and alphabet that give at least 40 bits validate; fewer are
     * refused naming both keys.
     *
     * @return void
     */
    public function testValidationRequiresTheLeastEntropy(): void
    {
        self::settingsWith(['alphabet' => '0123456789ABCDEF', 'length' => 10])->validate();
        self::settingsWith(['alphabet' => '0123', 'length' => 20])->validate();

        $settings = self::settingsWith(['alphabet' => '0123456789ABCDEF', 'length' => 9]);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('mfa.recovery_codes.length and mfa.recovery_codes.alphabet must give each code at least 40 bits of entropy after normalisation.');

        $settings->validate();
    }

    /**
     * Assert each value is refused with the message, as it is read and when
     * every setting is validated.
     *
     * @param  list<mixed>  $values
     * @param  string  $key
     * @param  \Closure(\SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeSettings): mixed  $read
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
     * Build the settings over an `mfa.recovery_codes` block.
     *
     * @param  array<string, mixed>  $block
     * @return \SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeSettings
     */
    private static function settingsWith(array $block): RecoveryCodeSettings
    {
        return new RecoveryCodeSettings(new Repository(['mfa' => ['recovery_codes' => $block]]));
    }
}
