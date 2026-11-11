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
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(WriteConnection::class)]
final class WriteConnectionTest extends TestCase
{
    /**
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
     * @return void
     */
    public function testRoutesAnEloquentBuilderToTheWriteConnection(): void
    {
        $query = Factor::query();

        self::assertSame($query, WriteConnection::query($query));
        self::assertTrue($query->getQuery()->useWritePdo);
    }

    /**
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
     * @param  \Illuminate\Database\Connection  $connection
     * @return bool
     */
    private function readsOnWriter(Connection $connection): bool
    {
        return (fn (): bool => $this->readOnWriteConnection)->call($connection);
    }
}
