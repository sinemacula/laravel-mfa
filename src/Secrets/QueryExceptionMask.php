<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Secrets;

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

            if (!$current instanceof \PDOException) {
                continue;
            }

            self::clearDriverText($current);
        }
    }

    /**
     * Mask every query exception in the chain whose SQL names one of the
     * package's tables, and leave the rest as they are: the report path sees an
     * application's own failures too.
     *
     * @param  \Throwable  $throwable
     * @return void
     */
    public static function maskPackageQueries(\Throwable $throwable): void
    {
        foreach (self::chain($throwable) as $current) {

            if (!$current instanceof QueryException || !self::namesAPackageTable($current->getSql())) {
                continue;
            }

            self::mask($current);
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
     * The string bindings of every query exception in the chain, emptying them.
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

            (new \ReflectionProperty(QueryException::class, 'bindings'))->setValue($current, []); // NOSONAR
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
