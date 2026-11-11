<?php

declare(strict_types = 1);

namespace Tests\Unit\Exceptions;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Exceptions\MissingDestinationException;
use SineMacula\Laravel\Mfa\Exceptions\SecretNotRevealedException;
use SineMacula\Laravel\Mfa\Exceptions\TableAlreadyExistsException;
use SineMacula\Laravel\Mfa\Exceptions\UnsupportedFactorException;
use SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException;

/**
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(MissingDestinationException::class)]
#[CoversClass(SecretNotRevealedException::class)]
#[CoversClass(TableAlreadyExistsException::class)]
#[CoversClass(UnsupportedFactorException::class)]
#[CoversClass(UnsupportedIdentifierException::class)]
final class PlainExceptionsTest extends TestCase
{
    /**
     * @return iterable<string, array{class-string<\Exception>, class-string<\Exception>}>
     */
    public static function exceptions(): iterable
    {
        yield 'missing destination' => [MissingDestinationException::class, \RuntimeException::class];
        yield 'table already exists' => [TableAlreadyExistsException::class, \RuntimeException::class];
        yield 'unsupported factor' => [UnsupportedFactorException::class, \RuntimeException::class];
        yield 'unsupported identifier' => [UnsupportedIdentifierException::class, \RuntimeException::class];

        // Misusing a secret's plaintext is a bug in the calling code.
        yield 'secret not revealed' => [SecretNotRevealedException::class, \LogicException::class];
    }

    /**
     * @param  class-string<\Exception>  $class
     * @param  class-string<\Exception>  $parent
     * @return void
     */
    #[DataProvider('exceptions')]
    public function testIsAFinalSubtypeKeepingItsMessage(string $class, string $parent): void
    {
        $exception = new $class('The message.');

        self::assertTrue((new \ReflectionClass($class))->isFinal());
        self::assertInstanceOf($parent, $exception);
        self::assertSame('The message.', $exception->getMessage());
    }
}
