<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Secrets;

use Illuminate\Database\DeadlockException;
use Illuminate\Database\QueryException;
use SineMacula\Laravel\Mfa\Database\TableNames;

/**
 * Strips a failed query's bound values from its exception chain in place,
 * whatever `zend.exception_ignore_args` and `mfa.secrets.redact` say.
 *
 * Messages are rebuilt from SQLSTATE, driver error number and placeholder SQL,
 * as searching for values would miss an escaped or truncated copy.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class QueryExceptionMask
{
    /** @var string Kept so outer transactions still detect the deadlock and skip a lost savepoint. */
    private const string DEADLOCK = 'deadlock detected';

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * @param  \Illuminate\Database\QueryException  $exception
     * @return void
     */
    public static function mask(QueryException $exception): void
    {
        $chain = self::chain($exception);

        ExceptionScrubber::scrubTraces($exception, SensitiveValues::known(...self::bindingsIn($chain)));

        $reason = self::reason($exception);

        foreach ($chain as $current) {

            self::rewriteMessage($current, $current === $exception ? self::summary($exception, $reason) : $reason);

            if ($current instanceof QueryException) {
                (new \ReflectionProperty(QueryException::class, 'bindings'))->setValue($current, []); // NOSONAR
            }

            if (!$current instanceof \PDOException) {
                continue;
            }

            self::clearDriverText($current);
        }
    }

    /**
     * For anything leaving a transaction the package opened.
     *
     * @param  \Throwable  $throwable
     * @return void
     */
    public static function maskChain(\Throwable $throwable): void
    {
        self::maskQueries($throwable, static fn (): bool => true);
    }

    /**
     * Leaves queries on other tables alone, as the report path also sees the
     * application's own failures.
     *
     * @param  \Throwable  $throwable
     * @return void
     */
    public static function maskPackageQueries(\Throwable $throwable): void
    {
        self::maskQueries($throwable, static fn (QueryException $query): bool => self::namesAPackageTable($query->getSql()));
    }

    /**
     * @param  \Throwable  $throwable
     * @param  \Closure(\Illuminate\Database\QueryException): bool  $picks
     * @return void
     */
    private static function maskQueries(\Throwable $throwable, \Closure $picks): void
    {
        $deadlocks = [];

        foreach (self::chain($throwable) as $current) {

            if ($current instanceof DeadlockException) {
                $deadlocks[] = $current;
            }

            if (!$current instanceof QueryException || !$picks($current)) {
                continue;
            }

            self::maskDeadlocks($deadlocks, $current);
            self::mask($current);
        }
    }

    /**
     * Runs before the query is masked, as a deadlock wrapper copies its message
     * and records the same callers.
     *
     * @param  list<\Illuminate\Database\DeadlockException>  $deadlocks
     * @param  \Illuminate\Database\QueryException  $query
     * @return void
     */
    private static function maskDeadlocks(array $deadlocks, QueryException $query): void
    {
        $sensitive = SensitiveValues::known(...self::bindingsIn(self::chain($query)));
        $message   = sprintf('%s: %s', self::DEADLOCK, self::summary($query, self::reason($query)));

        foreach ($deadlocks as $deadlock) {
            ExceptionScrubber::scrubTraces($deadlock, $sensitive);
            self::rewriteMessage($deadlock, $message);
        }
    }

    /**
     * @param  string  $sql
     * @return bool
     *
     * @throws \InvalidArgumentException
     */
    private static function namesAPackageTable(string $sql): bool
    {
        foreach (array_keys(TableNames::DEFAULTS) as $block) {
            if (str_contains($sql, TableNames::of($block))) {
                return true;
            }
        }

        return false;
    }

    /**
     * Each exception once, so a chain that loops back ends.
     *
     * @param  \Throwable  $throwable
     * @return list<\Throwable>
     */
    private static function chain(\Throwable $throwable): array
    {
        $chain = [];

        for ($current = $throwable; $current !== null && !in_array($current, $chain, true); $current = $current->getPrevious()) {
            $chain[] = $current;
        }

        return $chain;
    }

    /**
     * @param  list<\Throwable>  $chain
     * @return array<string>
     */
    private static function bindingsIn(array $chain): array
    {
        $bindings = [];

        foreach ($chain as $current) {

            if (!$current instanceof QueryException) {
                continue;
            }

            $bindings = [...$bindings, ...array_filter($current->getBindings(), is_string(...))];
        }

        return $bindings;
    }

    /**
     * SQLSTATE and driver error number, which cannot hold a value.
     *
     * @param  \Illuminate\Database\QueryException  $exception
     * @return string
     */
    private static function reason(QueryException $exception): string
    {
        $info   = is_array($exception->errorInfo) ? $exception->errorInfo : [];
        $state  = $info[0] ?? $exception->getCode();
        $number = $info[1] ?? null;
        $reason = sprintf('SQLSTATE[%s]', is_scalar($state) ? $state : '');

        return is_int($number) || is_string($number) ? sprintf('%s: driver error %s', $reason, $number) : $reason;
    }

    /**
     * @param  \Illuminate\Database\QueryException  $exception
     * @param  string  $reason
     * @return string
     */
    private static function summary(QueryException $exception, string $reason): string
    {
        return sprintf('%s (Connection: %s, SQL: %s)', $reason, $exception->getConnectionName(), $exception->getSql());
    }

    /**
     * Reflection, as neither `\Exception` nor `\Error` has a message setter.
     *
     * @param  \Throwable  $throwable
     * @param  string  $message
     * @return void
     */
    private static function rewriteMessage(\Throwable $throwable, string $message): void
    {
        (new \ReflectionProperty($throwable instanceof \Exception ? \Exception::class : \Error::class, 'message'))->setValue($throwable, $message); // NOSONAR
    }

    /**
     * The driver's text can quote a stored value.
     *
     * @param  \PDOException  $exception
     * @return void
     */
    private static function clearDriverText(\PDOException $exception): void
    {
        if (!is_array($exception->errorInfo) || !array_key_exists(2, $exception->errorInfo)) {
            return;
        }

        $exception->errorInfo[2] = null;
    }
}
