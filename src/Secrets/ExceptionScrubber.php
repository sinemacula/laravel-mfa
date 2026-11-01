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
 * every string the package's frames received, every value any frame marks as
 * sensitive (a `\SensitiveParameterValue` or a `RevealedSecret`), and every
 * value under a key naming a secret, a code or a destination is collected
 * before anything is scrubbed, and redacted wherever it appears in another
 * frame: a string equal to one, and a string containing one of six characters
 * or more. A code message (an `MfaCodeMessage`, or a queued job sending one)
 * becomes `[redacted]` in every frame, and its code and its recipients'
 * addresses are redacted from any string containing them, whatever their
 * length. Other arguments are kept, with the secrets in them redacted as
 * `Redactor` redacts a log context, and other objects are kept as they are.
 *
 * The values collected are redacted from the message of every exception in the
 * chain too, each occurrence replaced by `[redacted]`, and so is every
 * `otpauth://` provisioning URI. A caller that knows what it handed down, as
 * the delivery of a code does, gives those values to `scrub()`: they are
 * redacted from every message and every frame, whatever their length, and do
 * not depend on PHP recording arguments at all. The exception and every
 * previous one are scrubbed in place, and what one of them passed on is
 * redacted in all of them.
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
     * one, redacting the values known to be sensitive too, whatever their
     * length.
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
     * Scrub the message and the trace of the exception and of every previous
     * one, redacting the sensitive values given too, each as its kind is
     * redacted: those a log record holds, for an exception logged with it.
     *
     * @param  \Throwable  $throwable
     * @param  \SineMacula\Laravel\Mfa\Secrets\SensitiveValues  $sensitive
     * @return void
     *
     * @internal
     */
    public static function scrubWith(\Throwable $throwable, #[\SensitiveParameter] SensitiveValues $sensitive): void
    {
        $chain  = self::chain($throwable);
        $values = self::collect($chain)->with($sensitive);

        foreach ($chain as $current) {
            self::scrubMessage($current, $values);
            self::scrubTrace($current, $values);
        }
    }

    /**
     * The sensitive values the exception and every previous one recorded in
     * their traces, as `scrub()` collects them, read without scrubbing
     * anything, so a log record's message copied from the exception's can be
     * redacted of them first.
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
     * The sensitive values recorded in the traces of the chain.
     *
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
     * Redact every sensitive value and every provisioning URI in the
     * exception's message.
     *
     * @param  \Throwable  $throwable
     * @param  \SineMacula\Laravel\Mfa\Secrets\SensitiveValues  $values
     * @return void
     */
    private static function scrubMessage(\Throwable $throwable, SensitiveValues $values): void
    {
        self::property($throwable, 'message')->setValue($throwable, Redactor::redactMessage($throwable->getMessage(), $values)); // NOSONAR
    }

    /**
     * Scrub the arguments recorded in the exception's own trace.
     *
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
     * The frame with its arguments scrubbed: all of them for a frame that
     * touches the package; for any other, the secrets in them and the sensitive
     * values collected.
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
