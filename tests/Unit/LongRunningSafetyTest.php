<?php

declare(strict_types = 1);

namespace Tests\Unit;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\MfaServiceProvider;
use Symfony\Component\Finder\Finder;
use Tests\TestCase;

/**
 * Static checks that nothing carries one request or job into the next, so they
 * cover code added later; the request and job tests prove the behaviour.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(MfaServiceProvider::class)]
final class LongRunningSafetyTest extends TestCase
{
    /** @var string The namespace of the package's classes. */
    private const string NAMESPACE = 'SineMacula\Laravel\Mfa\\';

    /**
     * Reflection, so statics a class inherits, such as Eloquent's, are not
     * counted.
     *
     * @return void
     */
    public function testNoClassDeclaresAStaticProperty(): void
    {
        $found = [];

        foreach ($this->packageClasses() as $class) {

            $reflection = new \ReflectionClass($class);

            foreach ($reflection->getProperties(\ReflectionProperty::IS_STATIC) as $property) {

                if ($property->getDeclaringClass()->getName() !== $class) {
                    continue;
                }

                $found[] = $class . '::$' . $property->getName();
            }
        }

        self::assertSame([], $found);
    }

    /**
     * It would keep its value for the life of the process.
     *
     * @return void
     */
    public function testNoFileDeclaresAStaticVariable(): void
    {
        $found = [];

        foreach ($this->packageFiles() as $path) {

            $tokens = array_values(array_filter(
                \PhpToken::tokenize((string) file_get_contents($path)),
                static fn (\PhpToken $token): bool => !$token->isIgnorable(),
            ));

            foreach ($tokens as $position => $token) {

                $next     = $tokens[$position + 1] ?? null;
                $previous = $tokens[$position - 1] ?? null;

                // A property declares a visibility before `static`, or a type
                // after it; those are the reflection test's to find.
                if (!$token->is(T_STATIC) || $next === null || !$next->is(T_VARIABLE) || $previous?->is([T_PUBLIC, T_PROTECTED, T_PRIVATE]) === true) {
                    continue;
                }

                $found[] = $path . ':' . $token->line;
            }
        }

        self::assertSame([], $found);
    }

    /**
     * @return void
     */
    public function testOnlyTheRegistryIsShared(): void
    {
        $shared = [];

        foreach (array_keys($this->container()->getBindings()) as $abstract) {

            if (!str_starts_with($abstract, self::NAMESPACE) || !$this->container()->isShared($abstract)) {
                continue;
            }

            $shared[] = $abstract;
        }

        self::assertSame([], $shared);
        self::assertTrue($this->container()->isShared('mfa'));
    }

    /**
     * @return list<string>
     */
    private function packageFiles(): array
    {
        $paths = [];

        foreach (Finder::create()->files()->in(dirname(__DIR__, 2) . '/src')->name('*.php') as $file) {
            $paths[] = $file->getPathname();
        }

        sort($paths);

        return $paths;
    }

    /**
     * @return list<class-string>
     */
    private function packageClasses(): array
    {
        $source  = dirname(__DIR__, 2) . '/src/';
        $classes = [];

        foreach ($this->packageFiles() as $path) {

            /** @var class-string $class */
            $class = self::NAMESPACE . str_replace(['/', '.php'], ['\\', ''], substr($path, strlen($source)));

            if (!class_exists($class) && !trait_exists($class) && !enum_exists($class)) {
                continue;
            }

            $classes[] = $class;
        }

        self::assertNotSame([], $classes);

        return $classes;
    }
}
