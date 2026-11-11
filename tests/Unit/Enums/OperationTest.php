<?php

declare(strict_types = 1);

namespace Tests\Unit\Enums;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Enums\Operation;

/**
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Operation::class)]
final class OperationTest extends TestCase
{
    /**
     * Pinned so a rename fails.
     *
     * @return void
     */
    public function testOperationsAreTheStableNames(): void
    {
        self::assertSame([
            'ADD_FACTOR'              => 'mfa.add_factor',
            'REPLACE_FACTOR'          => 'mfa.replace_factor',
            'REMOVE_FACTOR'           => 'mfa.remove_factor',
            'GENERATE_RECOVERY_CODES' => 'mfa.generate_recovery_codes',
        ], array_column(Operation::cases(), 'value', 'name'));
    }

    /**
     * @return iterable<string, array{string, bool}>
     */
    public static function names(): iterable
    {
        yield 'one segment' => ['identifier_change', true];
        yield 'two segments' => ['mfa.add_factor', true];
        yield 'three segments with digits' => ['billing.v2.change_plan', true];
        yield 'one letter' => ['a', true];
        yield 'blank' => ['', false];
        yield 'capitals' => ['Mfa.add_factor', false];
        yield 'a leading digit' => ['2fa.add_factor', false];
        yield 'a segment starting with an underscore' => ['mfa._add', false];
        yield 'an empty segment' => ['mfa..add_factor', false];
        yield 'a trailing dot' => ['mfa.', false];
        yield 'a hyphen' => ['mfa.add-factor', false];
        yield 'a space' => ['mfa.add factor', false];
        yield 'a trailing newline' => ["mfa.add_factor\n", false];
        yield 'a leading newline' => ["\nmfa.add_factor", false];
    }

    /**
     * Lower-case dot-separated segments of letters, digits and underscores,
     * each starting with a letter.
     *
     * @param  string  $name
     * @param  bool  $isName
     * @return void
     */
    #[DataProvider('names')]
    public function testRecognizesTheFormOfAnOperationsName(string $name, bool $isName): void
    {
        self::assertSame($isName, Operation::isName($name));
    }

    /**
     * @return void
     */
    public function testEveryOperationIsNamedInThatForm(): void
    {
        foreach (Operation::cases() as $operation) {
            self::assertTrue(Operation::isName($operation->value));
        }
    }
}
