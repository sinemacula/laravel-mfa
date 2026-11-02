<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Hardening;

use Illuminate\Database\Connection;
use Illuminate\Database\QueryException;

/**
 * Counts the statements a connection runs and, once armed, fails one of them
 * with a real `QueryException`, whose message and driver text quote the string
 * bindings, as a driver reporting a duplicate value does, or as a deadlock when
 * asked, which Laravel raises as its `DeadlockException` inside a nested
 * transaction. The failure is raised once: whatever carries on past it is what
 * a test looks for.
 *
 * A callback cannot be taken off a connection, so a test registers one of these
 * and arms it as often as it needs.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class FailsTheNthQuery
{
    /** @var int The statements counted since the last arming. */
    public int $seen = 0;

    /** @var bool Whether the failure was raised. */
    public bool $fired = false;

    /** @var bool Whether the failure was raised inside a transaction. */
    public bool $firedInTransaction = false;

    /** @var bool Whether the failure was raised inside a nested transaction. */
    public bool $firedNested = false;

    /** @var string The statement that failed. */
    public string $failed = '';

    /** @var ?int The statement to fail, counted from one. */
    private ?int $failAt = null;

    /** @var bool Whether the statement fails as a deadlock. */
    private bool $deadlock = false;

    /**
     * Constructor.
     *
     * @param  \Illuminate\Database\Connection  $connection
     */
    public function __construct(Connection $connection)
    {
        $connection->beforeExecuting(function (string $query, array $bindings, Connection $connection): void {

            $this->seen++;

            if ($this->seen !== $this->failAt) {
                return;
            }

            $this->failAt             = null;
            $this->fired              = true;
            $this->firedInTransaction = $connection->transactionLevel() > 0;
            $this->firedNested        = $connection->transactionLevel() > 1;
            $this->failed             = $query;

            throw new QueryException((string) $connection->getName(), $query, $bindings, $this->deadlock ? self::deadlock($bindings) : self::driverFailure($bindings));
        });
    }

    /**
     * Fail the statement with the given number, counted from now; none when
     * given none.
     *
     * @param  ?int  $statement
     * @param  bool  $deadlock
     * @return void
     */
    public function arm(?int $statement = null, bool $deadlock = false): void
    {
        $this->seen               = 0;
        $this->failAt             = $statement;
        $this->deadlock           = $deadlock;
        $this->fired              = false;
        $this->firedInTransaction = false;
        $this->firedNested        = false;
        $this->failed             = '';
    }

    /**
     * What a driver raises, quoting what the statement bound.
     *
     * @param  array<int|string, mixed>  $bindings
     * @return \PDOException
     */
    private static function driverFailure(array $bindings): \PDOException
    {
        $quoted  = implode(', ', array_filter($bindings, is_string(...)));
        $failure = new \PDOException(sprintf('SQLSTATE[HY000]: General error: 1 could not store (%s)', $quoted));

        $failure->errorInfo = ['HY000', 1, sprintf('could not store (%s)', $quoted)];

        return $failure;
    }

    /**
     * What a driver raises for a deadlock, quoting what the statement bound.
     *
     * @param  array<int|string, mixed>  $bindings
     * @return \PDOException
     */
    private static function deadlock(array $bindings): \PDOException
    {
        $quoted  = implode(', ', array_filter($bindings, is_string(...)));
        $failure = new \PDOException(sprintf('SQLSTATE[40001]: Serialization failure: 1213 Deadlock found when trying to get lock (%s)', $quoted));

        $failure->errorInfo = ['40001', 1213, sprintf('Deadlock found when trying to get lock (%s)', $quoted)];

        (new \ReflectionProperty(\Exception::class, 'code'))->setValue($failure, '40001');

        return $failure;
    }
}
