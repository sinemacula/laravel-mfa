<?php

declare(strict_types = 1);

namespace Tests\Unit\Database;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Database\IndexName;

/**
 * 63 characters is the longest name every engine keeps.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(IndexName::class)]
final class IndexNameTest extends TestCase
{
    /**
     * @return void
     */
    public function testANameThatFitsIsTheTableAndTheSuffix(): void
    {
        self::assertSame('mfa_codes_owner_index', IndexName::for('mfa_codes', '_owner_index'));

        $table = str_repeat('t', 51);

        self::assertSame($table . '_owner_index', IndexName::for($table, '_owner_index'));
        self::assertSame(63, strlen(IndexName::for($table, '_owner_index')));
    }

    /**
     * @return void
     */
    public function testANameThatWouldNotFitIsCutShortAndHashed(): void
    {
        $table = 'mfa_' . str_repeat('t', 48);
        $name  = IndexName::for($table, '_owner_index');

        self::assertSame('mfa_' . str_repeat('t', 38) . '_' . substr(hash('sha256', $table), 0, 8) . '_owner_index', $name);
        self::assertSame(63, strlen($name));
        self::assertSame($name, IndexName::for($table, '_owner_index'));
    }
}
