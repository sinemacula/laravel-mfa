<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Secrets;

use SineMacula\Laravel\Mfa\Secrets\RevealedSecret;

/**
 * Gives an exception a trace of the test's choosing.
 *
 * Whether PHP records arguments in a trace depends on
 * `zend.exception_ignore_args`, which differs between development and
 * production configurations, so tests of trace scrubbing set the frames they
 * scrub rather than rely on what PHP recorded.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ForgedTrace
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * The exception, with its trace replaced by the frames.
     *
     * @template TThrowable of \Throwable
     *
     * @param  TThrowable  $throwable
     * @param  list<array<string, mixed>>  $frames
     * @return TThrowable
     */
    public static function onto(\Throwable $throwable, array $frames): \Throwable
    {
        $property = new \ReflectionProperty($throwable instanceof \Exception ? \Exception::class : \Error::class, 'trace');

        $property->setValue($throwable, $frames);

        return $throwable;
    }

    /**
     * The path of a file inside the package's source directory, as PHP loaded
     * the package's classes from it.
     *
     * @param  string  $relative
     * @return string
     */
    public static function packageFile(string $relative): string
    {
        return dirname((string) (new \ReflectionClass(RevealedSecret::class))->getFileName(), 2) . DIRECTORY_SEPARATOR . $relative;
    }
}
