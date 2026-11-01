<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Secrets;

/**
 * Throws for real with the arguments of every call recorded, and reads the
 * strings a trace recorded.
 *
 * Whether PHP records arguments in a trace depends on
 * `zend.exception_ignore_args`, which differs between development and
 * production configurations, so the setting is turned off for the call.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class RecordedTrace
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * The exception the call throws, with the arguments of every call in its
     * trace.
     *
     * @param  \Closure(): mixed  $call
     * @return \Throwable
     *
     * @throws \LogicException
     */
    public static function thrownBy(\Closure $call): \Throwable
    {
        $setting = ini_set('zend.exception_ignore_args', '0');

        try {
            $call();
        } catch (\Throwable $throwable) {
            return $throwable;
        } finally {
            ini_set('zend.exception_ignore_args', (string) $setting);
        }

        throw new \LogicException('The call threw nothing.');
    }

    /**
     * Every string the exception's trace recorded as an argument, at any depth.
     *
     * @param  \Throwable  $throwable
     * @return list<string>
     */
    public static function strings(\Throwable $throwable): array
    {
        return self::stringsIn(array_map(static fn (array $frame): mixed => $frame['args'] ?? [], $throwable->getTrace()));
    }

    /**
     * Every string in the value, at any depth.
     *
     * @param  mixed  $value
     * @return list<string>
     */
    private static function stringsIn(mixed $value): array
    {
        if (is_string($value)) {
            return [$value];
        }

        if (!is_array($value)) {
            return [];
        }

        return array_merge([], ...array_map(self::stringsIn(...), array_values($value)));
    }
}
