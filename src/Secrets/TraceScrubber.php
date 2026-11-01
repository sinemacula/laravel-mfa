<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Secrets;

/**
 * Scrubs the arguments an exception's trace recorded, so a secret, a code or a
 * full destination passed down the stack never reaches a log, an error tracker
 * or a rendered error page.
 *
 * A trace records every argument of every call unless PHP runs with
 * `zend.exception_ignore_args` on, and its string form shows the start of
 * each string. A frame cannot say which of its arguments is a code, so every
 * argument of a frame that touches this package is replaced with
 * `[redacted]`: a call into one of its classes, and a call made from one of
 * its files. Arguments of other frames are kept, with the secrets in them
 * redacted as `Redactor` redacts a log context. The exception and every
 * previous one are scrubbed in place.
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
final class TraceScrubber
{
    /** @var string The namespace of the package's classes. */
    private const string PACKAGE_NAMESPACE = 'SineMacula\Laravel\Mfa\\';

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Scrub the arguments recorded in the trace of the exception and of every
     * previous one.
     *
     * @param  \Throwable  $throwable
     * @return void
     */
    public static function scrub(\Throwable $throwable): void
    {
        $scrubbed = [];

        for ($current = $throwable; $current !== null && !isset($scrubbed[spl_object_id($current)]); $current = $current->getPrevious()) {
            $scrubbed[spl_object_id($current)] = true;

            self::scrubTrace($current);
        }
    }

    /**
     * Scrub the arguments recorded in the exception's own trace.
     *
     * @param  \Throwable  $throwable
     * @return void
     */
    private static function scrubTrace(\Throwable $throwable): void
    {
        $property = new \ReflectionProperty($throwable instanceof \Exception ? \Exception::class : \Error::class, 'trace');

        /** @var list<array<string, mixed>> $trace */
        $trace = $property->getValue($throwable);

        $property->setValue($throwable, array_map(self::scrubFrame(...), $trace));
    }

    /**
     * The frame with its arguments scrubbed: all of them for a frame that
     * touches the package, the secrets in them for any other.
     *
     * @param  array<string, mixed>  $frame
     * @return array<string, mixed>
     */
    private static function scrubFrame(array $frame): array
    {
        if (!isset($frame['args']) || !is_array($frame['args'])) {
            return $frame;
        }

        $frame['args'] = self::touchesThePackage($frame)
            ? array_map(static fn (): string => RevealedSecret::REDACTED, $frame['args'])
            : Redactor::redact($frame['args']);

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
}
