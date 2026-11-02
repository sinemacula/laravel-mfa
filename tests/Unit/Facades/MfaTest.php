<?php

declare(strict_types = 1);

namespace Tests\Unit\Facades;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\MfaManager;
use Tests\TestCase;

/**
 * The facade's annotations state the manager's surface exactly, so what an
 * application's editor and static analysis read is what the manager declares.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Mfa::class)]
#[CoversClass(MfaManager::class)]
final class MfaTest extends TestCase
{
    /** @var array{0: string, 1: string} The return and parameters of `extend()`, which `MfaManager` inherits, as the facade states them. */
    private const array EXTEND = [
        '\SineMacula\Laravel\Mfa\MfaManager',
        'string $driver, \Closure(\Illuminate\Contracts\Container\Container): \SineMacula\Laravel\Mfa\Contracts\FactorDriver $callback',
    ];

    /**
     * The facade reaches the manager the container holds.
     *
     * @return void
     */
    public function testTheFacadeResolvesTheManager(): void
    {
        self::assertInstanceOf(MfaManager::class, Mfa::getFacadeRoot());
        self::assertSame($this->container()->make('mfa'), Mfa::getFacadeRoot());
    }

    /**
     * Every public method the manager declares, and `extend()`, is annotated on
     * the facade, once, with the return its docblock states and the parameters
     * it declares, and nothing else is.
     *
     * @return void
     */
    public function testTheFacadeAnnotatesEveryManagerMethodAsDeclared(): void
    {
        $annotations = self::annotations();
        $expected    = self::expected();

        self::assertEqualsCanonicalizing(array_keys($expected), array_keys($annotations), 'The facade must annotate exactly the manager\'s surface.');

        foreach ($expected as $name => [$return, $parameters]) {
            self::assertSame(self::normalize($return), self::normalize($annotations[$name][0]), sprintf('The return of [%s] differs.', $name));
            self::assertSame(self::normalize($parameters), self::normalize($annotations[$name][1]), sprintf('The parameters of [%s] differ.', $name));
        }
    }

    /**
     * The forms the comparison treats as one type are one type, and what
     * differs in substance still differs.
     *
     * @return void
     */
    public function testTheComparisonTreatsEquivalentFormsAsOne(): void
    {
        self::assertSame(self::normalize('?int'), self::normalize('int|null'));
        self::assertSame(self::normalize('null|int|string'), self::normalize('string|int|null'));
        self::assertSame(self::normalize('array{a: int, b: ?int}'), self::normalize("array{\n    a: int,\n    b: ?int,\n}"));
        self::assertNotSame(self::normalize('array{a: ?int}'), self::normalize('array{a: int}'));
        self::assertNotSame(self::normalize('?int'), self::normalize('?string'));
    }

    /**
     * The facade's annotations, by method: the return and the parameters as
     * written, failing on a duplicate.
     *
     * @return array<string, array{0: string, 1: string}>
     */
    private static function annotations(): array
    {
        $docblock = (string) (new \ReflectionClass(Mfa::class))->getDocComment();

        preg_match_all('/^\s*\*\s*@method\s+static\s+(.+?)\s+(\w+)\((.*)\)\s*$/m', $docblock, $matches, PREG_SET_ORDER);

        $annotations = [];

        foreach ($matches as [, $return, $name, $parameters]) {
            self::assertArrayNotHasKey($name, $annotations, sprintf('The facade annotates [%s] twice.', $name));

            $annotations[$name] = [$return, $parameters];
        }

        return $annotations;
    }

    /**
     * What the facade must say of each method of the manager's surface: its
     * return and its parameters.
     *
     * @return array<string, array{0: string, 1: string}>
     */
    private static function expected(): array
    {
        $expected = [];

        foreach ((new \ReflectionClass(MfaManager::class))->getMethods(\ReflectionMethod::IS_PUBLIC) as $method) {
            if ($method->getDeclaringClass()->getName() !== MfaManager::class || str_starts_with($method->getName(), '__') || $method->getName() === 'setContainer') {
                continue;
            }

            $expected[$method->getName()] = [self::documentedReturn($method), self::declaredParameters($method)];
        }

        $expected['extend'] = self::EXTEND;

        return $expected;
    }

    /**
     * The return a method's docblock states.
     *
     * @param  \ReflectionMethod  $method
     * @return string
     */
    private static function documentedReturn(\ReflectionMethod $method): string
    {
        $docblock = (string) $method->getDocComment();

        self::assertSame(1, preg_match('/@return\s+(.+?)\n\s*\*\s*(?:\n|@|\/)/s', $docblock, $match), sprintf('[%s] must document its return.', $method->getName()));

        return (string) preg_replace('/\n\s*\*\s?/', "\n", $match[1]);
    }

    /**
     * The parameter list a method declares, the type of an untyped parameter
     * read from its docblock, as Laravel's `Manager` leaves its own untyped.
     *
     * @param  \ReflectionMethod  $method
     * @return string
     */
    private static function declaredParameters(\ReflectionMethod $method): string
    {
        $parameters = array_map(
            static fn (\ReflectionParameter $parameter): string => self::declaredParameter($method, $parameter),
            $method->getParameters(),
        );

        return implode(', ', $parameters);
    }

    /**
     * One parameter as an annotation writes it.
     *
     * @param  \ReflectionMethod  $method
     * @param  \ReflectionParameter  $parameter
     * @return string
     */
    private static function declaredParameter(\ReflectionMethod $method, \ReflectionParameter $parameter): string
    {
        $type = (string) $parameter->getType();

        if ($type === '') {
            $documented = preg_match('/@param\s+(\S+)\s+\$' . $parameter->getName() . '\b/', (string) $method->getDocComment(), $match);

            self::assertSame(1, $documented, sprintf('[%s] must document $%s.', $method->getName(), $parameter->getName()));

            $type = $match[1];
        }

        $declared = sprintf('%s $%s', self::qualify($type), $parameter->getName());

        return $parameter->isDefaultValueAvailable() ? sprintf('%s = %s', $declared, self::defaultOf($parameter)) : $declared;
    }

    /**
     * A type as an annotation writes it: every class named from the root.
     *
     * @param  string  $type
     * @return string
     */
    private static function qualify(string $type): string
    {
        return (string) preg_replace_callback(
            '/\\\?[A-Za-z_][\w\\\]*/',
            static fn (array $match): string => class_exists($match[0]) || interface_exists($match[0]) || enum_exists($match[0]) ? '\\' . ltrim($match[0], '\\') : $match[0],
            $type,
        );
    }

    /**
     * A parameter's default as an annotation writes it.
     *
     * @param  \ReflectionParameter  $parameter
     * @return string
     */
    private static function defaultOf(\ReflectionParameter $parameter): string
    {
        return strtolower(var_export($parameter->getDefaultValue(), true));
    }

    /**
     * The form two ways of writing one type share: no whitespace, no trailing
     * comma in a shape, `?T` as `T|null`, and a top-level union's members in
     * order. Parameter lists are compared parameter by parameter.
     *
     * @param  string  $signature
     * @return string
     */
    private static function normalize(string $signature): string
    {
        $flat = (string) preg_replace('/\s+/', ' ', trim($signature));
        $flat = (string) preg_replace('/,\s*([}\]>)])/', '$1', $flat);
        $flat = (string) preg_replace('/([{\[<(])\s+/', '$1', $flat);

        return implode(', ', array_map(self::normalizeParameter(...), self::splitTopLevel($flat, ',')));
    }

    /**
     * A parameter, or a bare type, in its normal form.
     *
     * @param  string  $parameter
     * @return string
     */
    private static function normalizeParameter(string $parameter): string
    {
        $parameter = trim($parameter);

        if (preg_match('/^(.*?)(\s+\$\w+.*)$/', $parameter, $match) === 1) {
            return self::normalizeType($match[1]) . $match[2];
        }

        return self::normalizeType($parameter);
    }

    /**
     * A type in its normal form: `?T` as `T|null`, and a union's members in
     * order.
     *
     * @param  string  $type
     * @return string
     */
    private static function normalizeType(string $type): string
    {
        $type = trim($type);

        if (str_starts_with($type, '?')) {
            $type = substr($type, 1) . '|null';
        }

        $members = array_map(trim(...), self::splitTopLevel($type, '|'));

        sort($members);

        return implode('|', $members);
    }

    /**
     * Split on the separator, outside brackets of any kind.
     *
     * @param  string  $value
     * @param  string  $separator
     * @return list<string>
     */
    private static function splitTopLevel(string $value, string $separator): array
    {
        $parts   = [];
        $current = '';
        $depth   = 0;

        foreach (str_split($value) as $character) {
            $depth += match ($character) {
                '(', '{', '<', '[' => 1,
                ')', '}', '>', ']' => -1,
                default            => 0,
            };

            if ($character === $separator && $depth === 0) {
                $parts[] = $current;
                $current = '';

                continue;
            }

            $current .= $character;
        }

        $parts[] = $current;

        return $parts;
    }
}
