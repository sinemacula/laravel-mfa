<?php

declare(strict_types = 1);

namespace Tests\Unit\Secrets;

use Illuminate\Config\Repository;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Secrets\SecretSettings;

/**
 * Tests for `SecretSettings`: redaction is on unless the setting reads as
 * false.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SecretSettings::class)]
final class SecretSettingsTest extends TestCase
{
    /**
     * Settings and whether each redacts.
     *
     * @return iterable<string, array{mixed, bool}>
     */
    public static function settings(): iterable
    {
        yield 'true' => [true, true];
        yield 'false' => [false, false];
        yield 'the string false' => ['false', false];
        yield 'zero' => [0, false];
        yield 'the string zero' => ['0', false];
        yield 'off' => ['off', false];
        yield 'no' => ['no', false];
        yield 'one' => [1, true];
        yield 'the string true' => ['true', true];
        yield 'null' => [null, true];
        yield 'an empty string' => ['', true];
        yield 'a malformed value' => ['sometimes', true];
    }

    /**
     * Redaction follows the setting, and fails safe on anything that does not
     * read as false.
     *
     * @param  mixed  $value
     * @param  bool  $redacts
     * @return void
     */
    #[DataProvider('settings')]
    public function testRedactsUnlessTheSettingReadsAsFalse(mixed $value, bool $redacts): void
    {
        $settings = new SecretSettings(new Repository(['mfa' => ['secrets' => ['redact' => $value]]]));

        self::assertSame($redacts, $settings->redacts());
    }

    /**
     * A missing block redacts.
     *
     * @return void
     */
    public function testRedactsWithoutTheBlock(): void
    {
        self::assertTrue((new SecretSettings(new Repository([])))->redacts());
    }
}
