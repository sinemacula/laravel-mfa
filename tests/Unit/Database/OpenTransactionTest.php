<?php

declare(strict_types = 1);

namespace Tests\Unit\Database;

use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Database\OpenTransaction;
use Tests\TestCase;

/**
 * Tests for `OpenTransaction`: work that must run in its caller's transaction
 * on the storage connection is refused without one, and allowed inside one.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(OpenTransaction::class)]
final class OpenTransactionTest extends TestCase
{
    /**
     * Without a transaction the work is refused with the message given.
     *
     * @return void
     */
    public function testRefusesWithoutATransaction(): void
    {
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('Needs a transaction.');

        OpenTransaction::assertOpen('Needs a transaction.');
    }

    /**
     * Inside a transaction the work goes ahead.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAllowsInsideATransaction(): void
    {
        DB::transaction(static function (): void {
            OpenTransaction::assertOpen('Needs a transaction.');
        });

        $this->addToAssertionCount(1);
    }
}
