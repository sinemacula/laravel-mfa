<?php

declare(strict_types = 1);

namespace Tests\Unit\Config;

use Illuminate\Config\Repository;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Config\IntegerSetting;

/**
 * Tests for `IntegerSetting`: how an integer setting is read, and what an
 * absent or malformed one falls back to.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(IntegerSetting::class)]
final class IntegerSettingTest extends TestCase
{
    /**
     * An absent setting reads as the default, even when a malformed fallback is
     * given.
     *
     * @return void
     */
    public function testAnAbsentSettingReadsAsTheDefault(): void
    {
        $config = new Repository(['mfa' => []]);

        self::assertSame(7, IntegerSetting::read($config, 'mfa.missing', 7));
        self::assertSame(7, IntegerSetting::read($config, 'mfa.missing', 7, 0));
    }

    /**
     * An integer setting reads as itself.
     *
     * @return void
     */
    public function testAnIntegerReadsAsItself(): void
    {
        $config = new Repository(['mfa' => ['value' => 12]]);

        self::assertSame(12, IntegerSetting::read($config, 'mfa.value', 7, 0));
    }

    /**
     * A numeric string reads as the integer it names.
     *
     * @return void
     */
    public function testANumericStringReadsAsItsInteger(): void
    {
        $config = new Repository(['mfa' => ['value' => '12']]);

        self::assertSame(12, IntegerSetting::read($config, 'mfa.value', 7, 0));
    }

    /**
     * A malformed setting reads as the malformed fallback.
     *
     * @return void
     */
    public function testAMalformedSettingReadsAsTheMalformedFallback(): void
    {
        $config = new Repository(['mfa' => ['value' => 'twelve']]);

        self::assertSame(0, IntegerSetting::read($config, 'mfa.value', 7, 0));
    }

    /**
     * A malformed setting reads as the default when no malformed fallback is
     * given.
     *
     * @return void
     */
    public function testAMalformedSettingReadsAsTheDefaultWithoutAFallback(): void
    {
        $config = new Repository(['mfa' => ['value' => null]]);

        self::assertSame(7, IntegerSetting::read($config, 'mfa.value', 7));
    }
}
