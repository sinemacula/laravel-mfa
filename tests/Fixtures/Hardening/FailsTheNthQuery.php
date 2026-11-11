<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Hardening;

use Illuminate\Database\Connection;
use Illuminate\Database\QueryException;

/**
 * Once armed, fails the nth statement once with a real `QueryException` quoting
 * the string bindings, or with a deadlock.
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
    /** @var int Statements counted since the last arming. */
    public int $seen = 0;

    /** @var bool */
    public bool $fired = false;

    /** @var bool */
    public bool $firedInTransaction = false;

    /** @var bool */
    public bool $firedNested = false;

    /** @var string */
    public string $failed = '';

    /** @var ?int Counted from one. */
    private ?int $failAt = null;

    /** @var bool */
    private bool $deadlock = false;

    /**
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
     * Counts from now; `null` fails nothing.
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
