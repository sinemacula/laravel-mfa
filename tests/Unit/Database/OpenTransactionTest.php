<?php

declare(strict_types = 1);

namespace Tests\Unit\Database;

use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Database\OpenTransaction;
use Tests\TestCase;

/**
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(OpenTransaction::class)]
final class OpenTransactionTest extends TestCase
{
    /**
     * @return void
     */
    public function testRefusesWithoutATransaction(): void
    {
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('Needs a transaction.');

        OpenTransaction::assertOpen('Needs a transaction.');
    }

    /**
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
