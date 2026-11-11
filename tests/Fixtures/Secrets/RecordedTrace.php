<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Secrets;

/**
 * Throws for real with or without trace arguments, setting
 * `zend.exception_ignore_args` for the call since its default varies.
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
     * @param  \Closure(): mixed  $call
     * @param  bool  $arguments
     * @return \Throwable
     *
     * @throws \LogicException
     */
    public static function thrownBy(\Closure $call, bool $arguments = true): \Throwable
    {
        $setting = ini_set('zend.exception_ignore_args', $arguments ? '0' : '1');

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
     * Every string argument in the trace, at any depth.
     *
     * @param  \Throwable  $throwable
     * @return list<string>
     */
    public static function strings(\Throwable $throwable): array
    {
        return self::stringsIn(array_map(static fn (array $frame): mixed => $frame['args'] ?? [], $throwable->getTrace()));
    }

    /**
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
