<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Testing\Seams;

use PHPUnit\Framework\Assert;

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
     * The call refuses by throwing a `RuntimeException`, never by returning or
     * by throwing anything else.
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
     * The values are integers, strings or `null`, never a model, an array or
     * any other object.
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
