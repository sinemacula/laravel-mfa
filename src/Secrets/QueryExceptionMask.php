<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Secrets;

use Illuminate\Database\DeadlockException;
use Illuminate\Database\QueryException;
use SineMacula\Laravel\Mfa\Database\TableNames;

/**
 * Takes the values a failed query was given out of its exception, in place,
 * keeping its class and code, so what a query bound never reaches a log, an
 * error tracker or a rendered error page, whatever `zend.exception_ignore_args`
 * and `mfa.secrets.redact` say.
 *
 * Laravel interpolates a query's bindings into a `QueryException`'s message and
 * keeps them on the exception, and a driver's own message can quote a stored
 * value, so no value is searched for and cut out, which an escaped or truncated
 * copy would survive. The message is rebuilt from what cannot hold one:
 *
 * - the `QueryException`'s message becomes its SQLSTATE, its driver error
 *   number, its connection's name and its SQL with placeholders;
 * - every previous exception's message becomes the SQLSTATE and the driver
 *   error number alone;
 * - the bindings are emptied, and the driver's text in `errorInfo` is cleared;
 * - the arguments its trace recorded are scrubbed as `ExceptionScrubber` scrubs
 *   them, with the bindings among the values it knows.
 *
 * Inside a nested transaction Laravel raises a concurrency failure as a
 * `DeadlockException` wrapping the query's, with the query's message copied
 * into it. That copy goes too, and the words Laravel looks for stay in its
 * place, so the transactions around it still treat it as what it is: one that
 * took it for something else would roll back to a savepoint a MySQL deadlock
 * has already discarded.
 *
 * A literal an application writes into its own raw SQL stays in the SQL, as
 * nothing can tell it from the query. The queries the package builds bind every
 * value.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class QueryExceptionMask
{
    /** @var string What Laravel recognises a concurrency failure by, as nothing else of a wrapper's message can stay. */
    private const string DEADLOCK = 'deadlock detected';

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Mask the query exception and every exception it wraps.
     *
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
     * Mask every query exception in the chain, and every deadlock exception
     * above one: what leaves a transaction the package opened, whatever it is.
     *
     * @param  \Throwable  $throwable
     * @return void
     */
    public static function maskChain(\Throwable $throwable): void
    {
        self::maskQueries($throwable, static fn (): bool => true);
    }

    /**
     * Mask every query exception in the chain whose SQL names one of the
     * package's tables, and every deadlock exception above one, and leave the
     * rest as they are: the report path sees an application's own failures too.
     *
     * @param  \Throwable  $throwable
     * @return void
     */
    public static function maskPackageQueries(\Throwable $throwable): void
    {
        self::maskQueries($throwable, static fn (QueryException $query): bool => self::namesAPackageTable($query->getSql()));
    }

    /**
     * Mask the query exceptions the check picks, and the deadlock exceptions
     * above each of them.
     *
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
     * Rewrite the message of each deadlock exception above the query exception,
     * before that is masked, and scrub its trace with the bindings, as it
     * records the same callers and so the same values.
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
     * Whether the SQL names one of the package's tables.
     *
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
     * The exception and every previous one, each once, so a chain that loops
     * back ends.
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
     * The string bindings of every query exception in the chain.
     *
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
     * What is left of why the query failed: the SQLSTATE and the driver error
     * number, when the driver gave them.
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
     * The message of the query exception: the reason, the connection and the
     * SQL with placeholders.
     *
     * @param  \Illuminate\Database\QueryException  $exception
     * @param  string  $reason
     * @return string
     */
    private static function summary(QueryException $exception, string $reason): string
    {
        return sprintf('%s (Connection: %s, SQL: %s)', $reason, $exception->getConnectionName(), $exception->getSql());
    }

    /**
     * Rewrite the exception's message. Neither `\Exception` nor `\Error` has a
     * setter for it, so it can only be rewritten in place through reflection.
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
     * Clear the driver's text from the exception's `errorInfo`, keeping the
     * SQLSTATE and the driver error number.
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
