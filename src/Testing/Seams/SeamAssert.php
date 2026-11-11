<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Testing\Seams;

use PHPUnit\Framework\Assert;
use SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException;

/**
 * Assertions the seam contracts share.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class SeamAssert
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * The call throws a `RuntimeException` and nothing else, never returns.
     *
     * @param  \Closure(): mixed  $call
     * @param  string  $message
     * @return void
     */
    public static function refusesByThrowing(\Closure $call, string $message): void
    {
        try {
            $call();
        } catch (\Throwable $exception) {
            Assert::assertInstanceOf(\RuntimeException::class, $exception, $message);

            return;
        }

        Assert::fail($message);
    }

    /**
     * Only `OperationRefusedException`, as the verification flow rolls back and
     * answers that one alone as a failure.
     *
     * @param  \Closure(): mixed  $call
     * @param  string  $message
     * @return void
     */
    public static function refusesWithAReason(\Closure $call, string $message): void
    {
        try {
            $call();
        } catch (\Throwable $exception) {
            Assert::assertInstanceOf(OperationRefusedException::class, $exception, $message);

            return;
        }

        Assert::fail($message);
    }

    /**
     * Each value is an int, string or `null`.
     *
     * @param  array<array-key, mixed>  $values
     * @param  string  $message
     * @return void
     */
    public static function scalars(array $values, string $message): void
    {
        $others = array_filter($values, static fn (mixed $value): bool => $value !== null && !is_int($value) && !is_string($value));

        Assert::assertSame([], $others, $message);
    }
}
