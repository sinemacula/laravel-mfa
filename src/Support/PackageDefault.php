<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Support;

use Illuminate\Container\Container;
use Illuminate\Contracts\Container\Container as ContainerContract;

/**
 * Binds a seam's default through a closure of this package's own, so an
 * application binding the same class by name is told apart from the default.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class PackageDefault
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Resolves the class as Laravel resolves a class bound by name.
     *
     * @param  \Illuminate\Contracts\Container\Container  $app
     * @param  string  $contract
     * @param  class-string  $class
     * @return void
     */
    public static function bind(ContainerContract $app, string $contract, string $class): void
    {
        // Container::resolve() is protected; this is the call its by-name closure makes
        $resolve = \Closure::bind(
            static fn (Container $container, string $class, array $parameters): mixed => $container->resolve($class, $parameters, raiseEvents: false),
            null,
            Container::class,
        );

        $app->bindIf($contract, static fn (Container $container, array $parameters = []): mixed => $resolve($container, $class, $parameters));
    }
}
