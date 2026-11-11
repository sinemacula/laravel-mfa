<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Secrets;

/**
 * Redacts secrets, codes and destinations from an exception chain's messages
 * and traces, since PHP records call arguments unless
 * `zend.exception_ignore_args` is on.
 *
 * A frame cannot say which argument is a code, so every argument of a frame
 * touching the package is redacted, and the strings it received are redacted
 * wherever else they appear. Reporters registered before the package booted see
 * the exception first: call `scrub()` ahead of them.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class ExceptionScrubber
{
    /** @var string */
    private const string PACKAGE_NAMESPACE = 'SineMacula\Laravel\Mfa\\';

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Known values the caller handed down are redacted whatever their length.
     *
     * @param  \Throwable  $throwable
     * @param  ?string  ...$known
     * @return void
     */
    public static function scrub(\Throwable $throwable, #[\SensitiveParameter] ?string ...$known): void
    {
        self::scrubWith($throwable, SensitiveValues::known(...$known));
    }

    /**
     * For an exception logged with a record, redacting the values it holds.
     *
     * @param  \Throwable  $throwable
     * @param  \SineMacula\Laravel\Mfa\Secrets\SensitiveValues  $sensitive
     * @return void
     *
     * @internal
     */
    public static function scrubWith(\Throwable $throwable, #[\SensitiveParameter] SensitiveValues $sensitive): void
    {
        QueryExceptionMask::maskPackageQueries($throwable);

        $chain  = self::chain($throwable);
        $values = self::collect($chain)->with($sensitive);

        foreach ($chain as $current) {
            self::scrubMessage($current, $values);
            self::scrubTrace($current, $values);
        }
    }

    /**
     * For a caller that rewrites the messages itself.
     *
     * @param  \Throwable  $throwable
     * @param  \SineMacula\Laravel\Mfa\Secrets\SensitiveValues  $sensitive
     * @return void
     *
     * @internal
     */
    public static function scrubTraces(\Throwable $throwable, #[\SensitiveParameter] SensitiveValues $sensitive): void
    {
        $chain  = self::chain($throwable);
        $values = self::collect($chain)->with($sensitive);

        foreach ($chain as $current) {
            self::scrubTrace($current, $values);
        }
    }

    /**
     * Read without scrubbing, so a log message copied from the exception can be
     * redacted first.
     *
     * @param  \Throwable  $throwable
     * @return \SineMacula\Laravel\Mfa\Secrets\SensitiveValues
     *
     * @internal
     */
    public static function sensitiveValuesOf(\Throwable $throwable): SensitiveValues
    {
        return self::collect(self::chain($throwable));
    }

    /**
     * @param  list<\Throwable>  $chain
     * @return \SineMacula\Laravel\Mfa\Secrets\SensitiveValues
     */
    private static function collect(array $chain): SensitiveValues
    {
        $values = SensitiveValues::none();

        foreach ($chain as $current) {
            foreach (self::traceOf($current) as $frame) {
                $arguments = $frame['args'] ?? null;

                if (!is_array($arguments)) {
                    continue;
                }

                $values = $values->with(SensitiveValues::inArguments($arguments, self::touchesThePackage($frame)));
            }
        }

        return $values;
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
     * @param  \Throwable  $throwable
     * @return list<array<string, mixed>>
     */
    private static function traceOf(\Throwable $throwable): array
    {
        /** @var list<array<string, mixed>> */
        return self::property($throwable, 'trace')->getValue($throwable); // NOSONAR
    }

    /**
     * @param  \Throwable  $throwable
     * @param  \SineMacula\Laravel\Mfa\Secrets\SensitiveValues  $values
     * @return void
     */
    private static function scrubMessage(\Throwable $throwable, SensitiveValues $values): void
    {
        self::property($throwable, 'message')->setValue($throwable, Redactor::redactMessage($throwable->getMessage(), $values)); // NOSONAR
    }

    /**
     * @param  \Throwable  $throwable
     * @param  \SineMacula\Laravel\Mfa\Secrets\SensitiveValues  $values
     * @return void
     */
    private static function scrubTrace(\Throwable $throwable, SensitiveValues $values): void
    {
        $trace = array_map(static fn (array $frame): array => self::scrubFrame($frame, $values), self::traceOf($throwable));

        self::property($throwable, 'trace')->setValue($throwable, $trace); // NOSONAR
    }

    /**
     * Redacts every argument of a frame touching the package.
     *
     * @param  array<string, mixed>  $frame
     * @param  \SineMacula\Laravel\Mfa\Secrets\SensitiveValues  $values
     * @return array<string, mixed>
     */
    private static function scrubFrame(array $frame, SensitiveValues $values): array
    {
        if (!isset($frame['args']) || !is_array($frame['args'])) {
            return $frame;
        }

        $frame['args'] = self::touchesThePackage($frame)
            ? array_map(static fn (): string => RevealedSecret::REDACTED, $frame['args'])
            : Redactor::arguments($frame['args'], $values);

        return $frame;
    }

    /**
     * A call into one of the package's classes, or from one of its files.
     *
     * @param  array<string, mixed>  $frame
     * @return bool
     */
    private static function touchesThePackage(array $frame): bool
    {
        $class = $frame['class'] ?? null;
        $file  = $frame['file']  ?? null;

        return (is_string($class) && str_starts_with($class, self::PACKAGE_NAMESPACE))
            || (is_string($file) && str_starts_with($file, dirname(__DIR__) . DIRECTORY_SEPARATOR));
    }

    /**
     * Reflection, as `\Exception` and `\Error` have no message or trace setter.
     *
     * @param  \Throwable  $throwable
     * @param  string  $name
     * @return \ReflectionProperty
     */
    private static function property(\Throwable $throwable, string $name): \ReflectionProperty
    {
        return new \ReflectionProperty($throwable instanceof \Exception ? \Exception::class : \Error::class, $name);
    }
}
