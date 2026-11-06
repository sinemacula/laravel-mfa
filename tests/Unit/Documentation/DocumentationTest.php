<?php

declare(strict_types = 1);

namespace Tests\Unit\Documentation;

use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Mfa\Applications\ApplicationBlock;
use SineMacula\Laravel\Mfa\Context\AuthenticationContextContributor;
use SineMacula\Laravel\Mfa\Context\CallerContext;
use SineMacula\Laravel\Mfa\Contracts\MfaEvent;
use SineMacula\Laravel\Mfa\Events\EventContext;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\MfaManager;
use Tests\TestCase;

/**
 * A drift guard for the README and the guides in docs/guides: every value of
 * the package's enums (the failure reasons and requirement parts among them),
 * every package event, every key of the event context and of the authentication
 * context, every configuration key and every key of an application's block, and
 * every method of the manager is documented, and every `Mfa::` call they show
 * exists.
 *
 * It catches an omission or a rename, not wrong prose: what the documentation
 * says about each of them is held to the code by review.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversNothing]
final class DocumentationTest extends TestCase
{
    /** @var list<string> Methods the manager declares only to refuse them, so never documented as calls. */
    private const array REFUSING_METHODS = ['__call', 'setContainer'];

    /** @var ?string The README and the guides, read once. */
    private static ?string $documentation = null;

    /**
     * Rows of `[enum value, enum]`: every case of every backed enum the package
     * ships.
     *
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function provideEnumValues(): iterable
    {
        foreach (self::classesIn('Enums') as $enum) {

            if (!is_subclass_of($enum, \BackedEnum::class)) {
                continue;
            }

            foreach ($enum::cases() as $case) {
                yield $enum . '::' . $case->name => [(string) $case->value, $enum];
            }
        }
    }

    /**
     * Every value of the package's enums is named in the documentation, in code
     * type.
     *
     * @param  string  $value
     * @param  string  $enum
     * @return void
     */
    #[DataProvider('provideEnumValues')]
    public function testEveryEnumValueIsDocumented(string $value, string $enum): void
    {
        self::assertTrue(str_contains(self::documentation(), '`' . $value . '`'), sprintf('The documentation does not name the %s value `%s`.', $enum, $value));
    }

    /**
     * Rows of `[event class]`: every event the package dispatches.
     *
     * @return iterable<string, array{0: class-string}>
     */
    public static function provideEvents(): iterable
    {
        foreach (self::classesIn('Events') as $class) {

            if (!is_a($class, MfaEvent::class, true) || (new \ReflectionClass($class))->isAbstract()) {
                continue;
            }

            yield (new \ReflectionClass($class))->getShortName() => [$class];
        }
    }

    /**
     * Every event the package dispatches has a row in the events guide's table.
     *
     * @param  class-string  $class
     * @return void
     */
    #[DataProvider('provideEvents')]
    public function testEveryEventIsInTheEventsTable(string $class): void
    {
        $name = (new \ReflectionClass($class))->getShortName();

        self::assertSame(1, preg_match('/^\| `' . $name . '` /m', self::documentation()), sprintf('The events table has no row for %s.', $name));
    }

    /**
     * Rows of `[key]`: every key of an event's context.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideEventContextKeys(): iterable
    {
        foreach (EventContext::KEYS as $key) {
            yield $key => [$key];
        }
    }

    /**
     * Every key of an event's context is named in the documentation.
     *
     * @param  string  $key
     * @return void
     */
    #[DataProvider('provideEventContextKeys')]
    public function testEveryEventContextKeyIsDocumented(string $key): void
    {
        self::assertTrue(str_contains(self::documentation(), '`' . $key . '`'), sprintf('The documentation does not name the event context key `%s`.', $key));
    }

    /**
     * Every key the package contributes to the authentication context is named
     * in the documentation. The keys are read from the contributor's neutral
     * answer, which has the keys of a full one.
     *
     * @return void
     */
    public function testEveryAuthenticationContextKeyIsDocumented(): void
    {
        $keys = array_keys(AuthenticationContextContributor::neutral());

        self::assertNotSame([], $keys);

        $undocumented = array_values(array_filter($keys, static fn (string $key): bool => !str_contains(self::documentation(), '`' . $key . '`')));

        self::assertSame([], $undocumented, 'The documentation does not name these authentication context keys.');
    }

    /**
     * Rows of `[key]`: every configuration key the package config ships.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideConfigurationKeys(): iterable
    {
        /** @var array<string, mixed> $config */
        $config = require dirname(__DIR__, 3) . '/config/mfa.php';

        foreach (self::leafKeys($config) as $key) {
            yield $key => [$key];
        }
    }

    /**
     * Every configuration key is named by its full path in the documentation.
     *
     * @param  string  $key
     * @return void
     */
    #[DataProvider('provideConfigurationKeys')]
    public function testEveryConfigurationKeyIsDocumented(string $key): void
    {
        self::assertTrue(str_contains(self::documentation(), '`' . $key . '`'), sprintf('The documentation does not name the configuration key `%s`.', $key));
    }

    /**
     * Rows of `[key]`: every key an application's block holds, by its path
     * within the block.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideApplicationKeys(): iterable
    {
        /** @var array<string, ?list<string>> $keys */
        $keys = (new \ReflectionClassConstant(ApplicationBlock::class, 'KEYS'))->getValue();

        foreach ($keys as $key => $nested) {
            foreach ($nested === null ? [$key] : array_map(static fn (string $member): string => $key . '.' . $member, $nested) as $path) {
                yield $path => [$path];
            }
        }
    }

    /**
     * Every key of an application's block is named by its path within the block
     * in the documentation.
     *
     * @param  string  $key
     * @return void
     */
    #[DataProvider('provideApplicationKeys')]
    public function testEveryApplicationKeyIsDocumented(string $key): void
    {
        self::assertTrue(str_contains(self::documentation(), '`' . $key . '`'), sprintf('The documentation does not name the application key `%s`.', $key));
    }

    /**
     * Rows of `[method]`: every public method the manager declares, but those
     * it declares only to refuse.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideManagerMethods(): iterable
    {
        foreach ((new \ReflectionClass(MfaManager::class))->getMethods(\ReflectionMethod::IS_PUBLIC) as $method) {

            if ($method->getDeclaringClass()->getName() !== MfaManager::class || in_array($method->getName(), self::REFUSING_METHODS, true)) {
                continue;
            }

            yield $method->getName() => [$method->getName()];
        }
    }

    /**
     * Every method the manager declares is shown being called.
     *
     * @param  string  $method
     * @return void
     */
    #[DataProvider('provideManagerMethods')]
    public function testEveryManagerMethodIsDocumented(string $method): void
    {
        self::assertSame(1, preg_match('/(::|->|`)' . $method . '\(/', self::documentation()), sprintf('The documentation does not show %s().', $method));
    }

    /**
     * Every `Mfa::name(` the documentation calls is a method of the manager,
     * its own or inherited, or of the facade.
     *
     * @return void
     */
    public function testEveryMfaCallTheDocumentationShowsExists(): void
    {
        preg_match_all('/\bMfa::(\w+)\(/', self::documentation(), $matches);

        self::assertNotSame([], $matches[1]);

        $unknown = array_values(array_filter(
            array_unique($matches[1]),
            static fn (string $method): bool => !method_exists(MfaManager::class, $method) && !method_exists(Mfa::class, $method),
        ));

        self::assertSame([], $unknown, 'The documentation calls Mfa methods that do not exist.');
    }

    /**
     * Every `Mfa::name(` the documentation shows with arguments, for a method
     * that takes the caller first, passes the caller first.
     *
     * @return void
     */
    public function testEveryCallerFirstCallTheDocumentationShowsPassesTheCaller(): void
    {
        $methods = [];

        foreach ((new \ReflectionClass(MfaManager::class))->getMethods(\ReflectionMethod::IS_PUBLIC) as $method) {

            $type = ($method->getParameters()[0] ?? null)?->getType();

            if (!$type instanceof \ReflectionNamedType || $type->getName() !== CallerContext::class) {
                continue;
            }

            $methods[] = $method->getName();
        }

        self::assertNotSame([], $methods);

        preg_match_all('/\bMfa::(' . implode('|', $methods) . ')\((?!\s*\))(?!\s*\$caller\b)(?!\s*CallerContext::)([^,)]*)/', self::documentation(), $matches);

        self::assertSame([], $matches[0], 'The documentation shows a call without the caller first.');
    }

    /**
     * The dotted paths of the configuration's settings: every key whose value
     * is not a map of further settings, a list and an empty array included.
     *
     * @param  array<array-key, mixed>  $config
     * @param  string  $prefix
     * @return list<string>
     */
    private static function leafKeys(array $config, string $prefix = ''): array
    {
        $keys = [];

        foreach ($config as $key => $value) {

            $path = $prefix . $key;

            if (!is_array($value) || $value === [] || array_is_list($value)) {
                $keys[] = $path;

                continue;
            }

            array_push($keys, ...self::leafKeys($value, $path . '.'));
        }

        return $keys;
    }

    /**
     * The classes of a top-level namespace of the package, by the files in its
     * directory.
     *
     * @param  string  $namespace
     * @return list<class-string>
     */
    private static function classesIn(string $namespace): array
    {
        $classes = [];

        foreach (glob(dirname(__DIR__, 3) . '/src/' . $namespace . '/*.php') ?: [] as $file) {

            /** @var class-string $class */
            $class = 'SineMacula\Laravel\Mfa\\' . $namespace . '\\' . basename($file, '.php');

            $classes[] = $class;
        }

        return $classes;
    }

    /**
     * The text of the README and every guide.
     *
     * @return string
     */
    private static function documentation(): string
    {
        $root  = dirname(__DIR__, 3);
        $files = [$root . '/README.md', ...(glob($root . '/docs/guides/*.md') ?: [])];

        return self::$documentation ??= implode("\n", array_map(static fn (string $file): string => (string) file_get_contents($file), $files));
    }
}
