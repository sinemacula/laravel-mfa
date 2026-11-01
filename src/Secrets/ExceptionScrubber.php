<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Secrets;

/**
 * Scrubs an exception of the secrets, codes and full destinations it recorded,
 * so none passed down the stack reaches a log, an error tracker or a rendered
 * error page.
 *
 * A trace records every argument of every call unless PHP runs with
 * `zend.exception_ignore_args` on, and its string form shows the start of each
 * string. A frame cannot say which of its arguments is a code, so every
 * argument of a frame that touches this package is replaced with `[redacted]`:
 * a call into one of its classes, and a call made from one of its files.
 *
 * What the package passes on travels further down the stack, and up it too: a
 * facade call records the code in the facade's frame, and the code the package
 * hands to a hasher or an encrypter is recorded again in every frame below. So
 * every string the package's frames received, and every value any frame marks
 * as sensitive (a `\SensitiveParameterValue` or a `RevealedSecret`), is
 * redacted wherever it appears in another frame: a string equal to one, and a
 * string containing one of six characters or more. Other arguments are kept,
 * with the secrets in them redacted as `Redactor` redacts a log context, and
 * objects are kept as they are.
 *
 * An `otpauth://` provisioning URI in an exception's message is redacted too.
 * The exception and every previous one are scrubbed in place, and what one of
 * them passed on is redacted in all of them.
 *
 * The package scrubs every exception the application's exception handler
 * reports, and every exception in a log record's context, unless
 * `mfa.secrets.redact` is off. An error reporter registered on the handler
 * before the package booted sees the exception first: call `scrub()` from the
 * application's own `report` callback ahead of it, or run PHP with
 * `zend.exception_ignore_args` on, as its production configuration does.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class ExceptionScrubber
{
    /** @var string The namespace of the package's classes. */
    private const string PACKAGE_NAMESPACE = 'SineMacula\Laravel\Mfa\\';

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Scrub the message and the trace of the exception and of every previous
     * one.
     *
     * @param  \Throwable  $throwable
     * @return void
     */
    public static function scrub(\Throwable $throwable): void
    {
        $chain  = self::chain($throwable);
        $passed = [];

        foreach ($chain as $current) {
            foreach (self::traceOf($current) as $frame) {
                array_push($passed, ...self::passedOn($frame));
            }
        }

        $passed = array_values(array_unique($passed));

        foreach ($chain as $current) {
            self::scrubMessage($current);
            self::scrubTrace($current, $passed);
        }
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
     * The trace recorded in the exception.
     *
     * @param  \Throwable  $throwable
     * @return list<array<string, mixed>>
     */
    private static function traceOf(\Throwable $throwable): array
    {
        /** @var list<array<string, mixed>> */
        return self::property($throwable, 'trace')->getValue($throwable); // NOSONAR
    }

    /**
     * The strings the frame passed on that must not appear in any frame: every
     * string among the arguments of a frame that touches the package, and every
     * value any frame marks as sensitive.
     *
     * @param  array<string, mixed>  $frame
     * @return list<string>
     */
    private static function passedOn(array $frame): array
    {
        $arguments = $frame['args'] ?? null;

        return is_array($arguments) ? self::stringsIn($arguments, self::touchesThePackage($frame), 0) : [];
    }

    /**
     * The strings in the value worth redacting elsewhere: every one when all
     * are, and otherwise only those a sensitive value holds.
     *
     * @param  mixed  $value
     * @param  bool  $all
     * @param  int  $depth
     * @return list<string>
     */
    private static function stringsIn(mixed $value, bool $all, int $depth): array
    {
        if ($depth > Redactor::MAX_DEPTH) {
            return [];
        }

        return match (true) {
            $value instanceof \SensitiveParameterValue => self::stringsIn($value->getValue(), true, $depth + 1),
            $value instanceof RevealedSecret           => self::stringsIn($value->reveal(), true, $depth + 1),
            is_string($value)                          => $all && $value !== '' && $value !== RevealedSecret::REDACTED ? [$value] : [],
            is_array($value)                           => self::stringsInEach($value, $all, $depth),
            default                                    => [],
        };
    }

    /**
     * The strings worth redacting elsewhere in each item of the array.
     *
     * @param  array<array-key, mixed>  $values
     * @param  bool  $all
     * @param  int  $depth
     * @return list<string>
     */
    private static function stringsInEach(array $values, bool $all, int $depth): array
    {
        $strings = [];

        foreach ($values as $value) {
            array_push($strings, ...self::stringsIn($value, $all, $depth + 1));
        }

        return $strings;
    }

    /**
     * Redact every provisioning URI in the exception's message.
     *
     * @param  \Throwable  $throwable
     * @return void
     */
    private static function scrubMessage(\Throwable $throwable): void
    {
        self::property($throwable, 'message')->setValue($throwable, Redactor::redactString($throwable->getMessage())); // NOSONAR
    }

    /**
     * Scrub the arguments recorded in the exception's own trace.
     *
     * @param  \Throwable  $throwable
     * @param  list<string>  $passed
     * @return void
     */
    private static function scrubTrace(\Throwable $throwable, array $passed): void
    {
        $trace = array_map(static fn (array $frame): array => self::scrubFrame($frame, $passed), self::traceOf($throwable));

        self::property($throwable, 'trace')->setValue($throwable, $trace); // NOSONAR
    }

    /**
     * The frame with its arguments scrubbed: all of them for a frame that
     * touches the package; for any other, the secrets in them and the values
     * passed on.
     *
     * @param  array<string, mixed>  $frame
     * @param  list<string>  $passed
     * @return array<string, mixed>
     */
    private static function scrubFrame(array $frame, array $passed): array
    {
        if (!isset($frame['args']) || !is_array($frame['args'])) {
            return $frame;
        }

        $frame['args'] = self::touchesThePackage($frame)
            ? array_map(static fn (): string => RevealedSecret::REDACTED, $frame['args'])
            : Redactor::arguments($frame['args'], $passed);

        return $frame;
    }

    /**
     * Whether the frame is a call into one of the package's classes, or a call
     * made from one of its files.
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
     * A property of `\Exception` or `\Error`. Neither has a setter for its
     * message or its trace, so they can only be rewritten in place through
     * reflection.
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
