<?php

declare(strict_types = 1);

namespace Tests\Unit\Database;

use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Database\AfterStorageCommit;
use Tests\TestCase;

/**
 * Work that follows a change to the package's tables runs once the change has
 * committed on the storage connection: at once with no transaction open there,
 * at the commit otherwise, never on a rollback, and without waiting for a
 * transaction on another connection.
 *
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
     * With no transaction open, the work runs at once.
     *
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
     * Inside a transaction, the work waits for the outermost commit.
     *
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
     * A transaction that rolls back never runs the work.
     *
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
     * A transaction open on another connection does not hold the work back.
     *
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
     * Count a run of the work.
     *
     * @return void
     */
    private function work(): void
    {
        $this->runs++;
    }
}
