<?php

declare(strict_types = 1);

namespace Tests\Unit\Database;

use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Database\AfterStorageCommit;
use Tests\TestCase;

/**
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AfterStorageCommit::class)]
final class AfterStorageCommitTest extends TestCase
{
    /** @var int How many times the work has run. */
    private int $runs = 0;

    /**
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testRunsAtOnceWithNoTransactionOpen(): void
    {
        AfterStorageCommit::run($this->container(), $this->work(...));

        self::assertSame(1, $this->runs);
    }

    /**
     * @return void
     *
     * @throws \Throwable
     */
    public function testRunsOnceTheOutermostTransactionCommits(): void
    {
        $connection = DB::connection();

        $connection->beginTransaction();
        $connection->beginTransaction();

        AfterStorageCommit::run($this->container(), $this->work(...));

        $connection->commit();

        self::assertSame(0, $this->runs);

        $connection->commit();

        self::assertSame(1, $this->runs);
    }

    /**
     * @return void
     *
     * @throws \Throwable
     */
    public function testNeverRunsWhenTheTransactionRollsBack(): void
    {
        $connection = DB::connection();

        $connection->beginTransaction();

        AfterStorageCommit::run($this->container(), $this->work(...));

        $connection->rollBack();

        self::assertSame(0, $this->runs);
    }

    /**
     * @return void
     *
     * @throws \Throwable
     */
    public function testATransactionOnAnotherConnectionDoesNotHoldItBack(): void
    {
        config()->set('database.connections.other', config('database.connections.testing'));

        $other = DB::connection('other');

        $other->beginTransaction();

        try {
            AfterStorageCommit::run($this->container(), $this->work(...));

            self::assertSame(1, $this->runs);
        } finally {
            $other->rollBack();
        }
    }

    /**
     * @return void
     */
    private function work(): void
    {
        $this->runs++;
    }
}
