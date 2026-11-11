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
 * Drift guard: every enum value, event, context key, configuration key,
 * application key and manager method is documented, and every `Mfa::` call
 * shown exists. It catches omissions and renames, not wrong prose.
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
     * Each is named in code type.
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
     * @return iterable<string, array{0: string}>
     */
    public static function provideEventContextKeys(): iterable
    {
        foreach (EventContext::KEYS as $key) {
            yield $key => [$key];
        }
    }

    /**
     * @param  string  $key
     * @return void
     */
    #[DataProvider('provideEventContextKeys')]
    public function testEveryEventContextKeyIsDocumented(string $key): void
    {
        self::assertTrue(str_contains(self::documentation(), '`' . $key . '`'), sprintf('The documentation does not name the event context key `%s`.', $key));
    }

    /**
     * The keys are read from the contributor's neutral answer, which has a full
     * one's keys.
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
     * @param  string  $key
     * @return void
     */
    #[DataProvider('provideConfigurationKeys')]
    public function testEveryConfigurationKeyIsDocumented(string $key): void
    {
        self::assertTrue(str_contains(self::documentation(), '`' . $key . '`'), sprintf('The documentation does not name the configuration key `%s`.', $key));
    }

    /**
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
     * @param  string  $key
     * @return void
     */
    #[DataProvider('provideApplicationKeys')]
    public function testEveryApplicationKeyIsDocumented(string $key): void
    {
        self::assertTrue(str_contains(self::documentation(), '`' . $key . '`'), sprintf('The documentation does not name the application key `%s`.', $key));
    }

    /**
     * Every public method the manager declares, but those it declares only to
     * refuse.
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
     * @param  string  $method
     * @return void
     */
    #[DataProvider('provideManagerMethods')]
    public function testEveryManagerMethodIsDocumented(string $method): void
    {
        self::assertSame(1, preg_match('/(::|->|`)' . $method . '\(/', self::documentation()), sprintf('The documentation does not show %s().', $method));
    }

    /**
     * Its own, inherited, or the facade's.
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
     * Dotted paths of every key whose value is not a map of further settings;
     * lists and empty arrays count as settings.
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
     * Read from the files in its directory.
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
     * @return string
     */
    private static function documentation(): string
    {
        $root  = dirname(__DIR__, 3);
        $files = [$root . '/README.md', ...(glob($root . '/docs/guides/*.md') ?: [])];

        return self::$documentation ??= implode("\n", array_map(static fn (string $file): string => (string) file_get_contents($file), $files));
    }
}
