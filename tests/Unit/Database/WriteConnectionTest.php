<?php

declare(strict_types = 1);

namespace Tests\Unit\Database;

use Illuminate\Database\Connection;
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

    /**
     * The callback runs with reads on the model's connection routed to the
     * writer, gets its answer back, and the earlier mode is put back.
     *
     * @return void
     */
    public function testDuringRoutesReadsAndRestoresTheMode(): void
    {
        $factor     = new Factor;
        $connection = $factor->getConnection();

        self::assertFalse($this->readsOnWriter($connection));

        $answer = WriteConnection::during($factor, function () use ($connection): string {
            self::assertTrue($this->readsOnWriter($connection));

            return 'answer';
        });

        self::assertSame('answer', $answer);
        self::assertFalse($this->readsOnWriter($connection));
    }

    /**
     * Nested inside itself, and on a connection already routed by whoever else,
     * the outer mode is what comes back.
     *
     * @return void
     */
    public function testDuringKeepsAnEarlierMode(): void
    {
        $factor     = new Factor;
        $connection = $factor->getConnection();

        WriteConnection::during($factor, function () use ($factor, $connection): void {
            WriteConnection::during($factor, static fn (): null => null);

            self::assertTrue($this->readsOnWriter($connection));
        });

        self::assertFalse($this->readsOnWriter($connection));

        $connection->useWriteConnectionWhenReading();

        WriteConnection::during($factor, static fn (): null => null);

        self::assertTrue($this->readsOnWriter($connection));

        $connection->useWriteConnectionWhenReading(false);
    }

    /**
     * The earlier mode comes back after the callback throws, and the exception
     * is passed on.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testDuringRestoresTheModeAfterAnException(): void
    {
        $factor     = new Factor;
        $connection = $factor->getConnection();

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('The read failed.');

        try {
            WriteConnection::during($factor, static function (): never {
                throw new \RuntimeException('The read failed.');
            });
        } finally {
            self::assertFalse($this->readsOnWriter($connection));
        }
    }

    /**
     * Whether the connection routes reads to the writer.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @return bool
     */
    private function readsOnWriter(Connection $connection): bool
    {
        return (fn (): bool => $this->readOnWriteConnection)->call($connection);
    }
}
