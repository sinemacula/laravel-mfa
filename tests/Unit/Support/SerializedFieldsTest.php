<?php

declare(strict_types = 1);

namespace Tests\Unit\Support;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Enums\KeyProtection;
use SineMacula\Laravel\Mfa\Support\SerializedFields;

/**
 * Unit tests for `SerializedFields`, the typed reader the values use to read
 * their serialised form back.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SerializedFields::class)]
final class SerializedFieldsTest extends TestCase
{
    /**
     * Each reader returns a field of its type as it is.
     *
     * @return void
     */
    public function testEachReaderReturnsAFieldOfItsType(): void
    {
        $fields = new SerializedFields([
            'string' => 'value',
            'empty'  => '',
            'bool'   => false,
            'int'    => 0,
            'array'  => ['nested' => true, 'other' => 1],
            'list'   => [],
            'enum'   => 'hardware',
        ], 'a sample');

        self::assertSame('value', $fields->string('string'));
        self::assertSame('', $fields->string('empty'));
        self::assertSame('value', $fields->nullableString('string'));
        self::assertFalse($fields->nullableBool('bool'));
        self::assertSame(0, $fields->int('int'));
        self::assertSame(0, $fields->nullableInt('int'));
        self::assertSame(['nested' => true, 'other' => 1], $fields->array('array'));
        self::assertSame([], $fields->array('list'));
        self::assertSame(['nested' => true, 'other' => 1], $fields->nullableArray('array'));
        self::assertSame(KeyProtection::HARDWARE, $fields->enum('enum', KeyProtection::class));
        self::assertSame(KeyProtection::HARDWARE, $fields->nullableEnum('enum', KeyProtection::class));
    }

    /**
     * A nullable reader returns null for a missing field or a null one.
     *
     * @return void
     */
    public function testANullableReaderReturnsNullForAMissingOrNullField(): void
    {
        $fields = new SerializedFields(['null' => null], 'a sample');

        foreach (['null', 'missing'] as $key) {
            self::assertNull($fields->nullableString($key));
            self::assertNull($fields->nullableBool($key));
            self::assertNull($fields->nullableInt($key));
            self::assertNull($fields->nullableArray($key));
            self::assertNull($fields->nullableEnum($key, KeyProtection::class));
        }
    }

    /**
     * Only the known fields pass, whether they are present or not.
     *
     * @return void
     */
    public function testKnownFieldsPass(): void
    {
        $this->expectNotToPerformAssertions();

        (new SerializedFields(['string' => 'value', 'null' => null], 'a sample'))->refuseUnknown('string', 'null', 'missing');
        (new SerializedFields([], 'a sample'))->refuseUnknown();
    }

    /**
     * Forms that hold a field the reader does not know.
     *
     * @return iterable<string, array{array<array-key, mixed>, string}>
     */
    public static function provideUnknownFields(): iterable
    {
        yield 'a mistyped key' => [['string' => 'value', 'strnig' => 'value'], 'The [strnig] field of a sample is not a known field.'];
        yield 'a key that differs in case' => [['String' => 'value'], 'The [String] field of a sample is not a known field.'];
        yield 'a list key' => [['value'], 'The [0] field of a sample is not a known field.'];
        yield 'a null field' => [['extra' => null], 'The [extra] field of a sample is not a known field.'];
    }

    /**
     * A field the reader does not know is refused, so a mistyped key is never
     * read as a missing one.
     *
     * @param  array<array-key, mixed>  $data
     * @param  string  $message
     * @return void
     */
    #[DataProvider('provideUnknownFields')]
    public function testAnUnknownFieldIsRefused(array $data, string $message): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage($message);

        (new SerializedFields($data, 'a sample'))->refuseUnknown('string', 'null');
    }

    /**
     * Fields that are not of the type read.
     *
     * @return iterable<string, array{callable(\SineMacula\Laravel\Mfa\Support\SerializedFields): mixed, string}>
     */
    public static function provideMistypedFields(): iterable
    {
        yield 'a missing string' => [static fn (SerializedFields $fields): mixed => $fields->string('missing'), 'The [missing] field of a sample must be a string.'];
        yield 'a null string' => [static fn (SerializedFields $fields): mixed => $fields->string('null'), 'The [null] field of a sample must be a string.'];
        yield 'an integer as a string' => [static fn (SerializedFields $fields): mixed => $fields->string('int'), 'The [int] field of a sample must be a string.'];
        yield 'an integer as a nullable string' => [
            static fn (SerializedFields $fields): mixed => $fields->nullableString('int'),
            'The [int] field of a sample must be a string or null.',
        ];
        yield 'an integer as a boolean' => [static fn (SerializedFields $fields): mixed => $fields->nullableBool('int'), 'The [int] field of a sample must be a boolean or null.'];
        yield 'a string as an integer' => [static fn (SerializedFields $fields): mixed => $fields->int('string'), 'The [string] field of a sample must be an integer.'];
        yield 'a missing integer' => [static fn (SerializedFields $fields): mixed => $fields->int('missing'), 'The [missing] field of a sample must be an integer.'];
        yield 'a float as a nullable integer' => [
            static fn (SerializedFields $fields): mixed => $fields->nullableInt('float'),
            'The [float] field of a sample must be an integer or null.',
        ];
        yield 'a string as an array' => [static fn (SerializedFields $fields): mixed => $fields->array('string'), 'The [string] field of a sample must be an array.'];
        yield 'a missing array' => [static fn (SerializedFields $fields): mixed => $fields->array('missing'), 'The [missing] field of a sample must be an array.'];
        yield 'a string as a nullable array' => [
            static fn (SerializedFields $fields): mixed => $fields->nullableArray('string'),
            'The [string] field of a sample must be an array or null.',
        ];
        yield 'a missing enum' => [
            static fn (SerializedFields $fields): mixed => $fields->enum('missing', KeyProtection::class),
            'The [missing] field of a sample must be a string.',
        ];
        yield 'an unknown enum value' => [
            static fn (SerializedFields $fields): mixed => $fields->enum('string', KeyProtection::class),
            'The [string] field of a sample is not a known value.',
        ];
        yield 'an integer as an enum' => [
            static fn (SerializedFields $fields): mixed => $fields->nullableEnum('int', KeyProtection::class),
            'The [int] field of a sample must be a string or null.',
        ];
        yield 'an unknown nullable enum value' => [
            static fn (SerializedFields $fields): mixed => $fields->nullableEnum('string', KeyProtection::class),
            'The [string] field of a sample is not a known value.',
        ];
    }

    /**
     * A field that is not of the type read is refused, naming the field and
     * what it belongs to.
     *
     * @param  callable(\SineMacula\Laravel\Mfa\Support\SerializedFields): mixed  $read
     * @param  string  $message
     * @return void
     */
    #[DataProvider('provideMistypedFields')]
    public function testAMistypedFieldIsRefused(callable $read, string $message): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage($message);

        $read(new SerializedFields(['null' => null, 'int' => 1, 'float' => 1.5, 'string' => 'value'], 'a sample'));
    }
}
