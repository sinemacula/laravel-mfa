<?php

declare(strict_types = 1);

namespace Tests\Unit\Database;

use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Database\WriteConnection;
use SineMacula\Laravel\Mfa\Models\Factor;
use Tests\TestCase;

/**
 * Unit tests for `WriteConnection`: the query it is handed is routed to the
 * write connection and handed back.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(WriteConnection::class)]
final class WriteConnectionTest extends TestCase
{
    /**
     * A query builder is routed to the write connection and returned as it is.
     *
     * @return void
     */
    public function testRoutesAQueryBuilderToTheWriteConnection(): void
    {
        $query = DB::table('mfa_factors');

        self::assertFalse($query->useWritePdo);
        self::assertSame($query, WriteConnection::query($query));
        self::assertTrue($query->useWritePdo);
    }

    /**
     * An Eloquent builder is routed to the write connection through its
     * underlying query and returned as it is.
     *
     * @return void
     */
    public function testRoutesAnEloquentBuilderToTheWriteConnection(): void
    {
        $query = Factor::query();

        self::assertSame($query, WriteConnection::query($query));
        self::assertTrue($query->getQuery()->useWritePdo);
    }
}
