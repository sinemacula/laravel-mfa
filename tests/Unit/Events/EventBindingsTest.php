<?php

declare(strict_types = 1);

namespace Tests\Unit\Events;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Context\DefaultEventContextResolver;
use SineMacula\Laravel\Mfa\Contracts\EventContextResolver;
use SineMacula\Laravel\Mfa\Events\EventBindings;
use SineMacula\Laravel\Mfa\Events\EventDispatcher;
use Tests\TestCase;

/**
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(EventBindings::class)]
final class EventBindingsTest extends TestCase
{
    /**
     * @return void
     */
    public function testBuildsTheResolverAndTheDispatcherOnEveryResolution(): void
    {
        $app = $this->container();

        $app->forgetInstance(EventContextResolver::class);
        $app->forgetInstance(EventDispatcher::class);

        EventBindings::register($app);

        self::assertInstanceOf(DefaultEventContextResolver::class, $app->make(EventContextResolver::class));
        self::assertNotSame($app->make(EventContextResolver::class), $app->make(EventContextResolver::class));
        self::assertTrue($app->bound(EventDispatcher::class));
        self::assertNotSame($app->make(EventDispatcher::class), $app->make(EventDispatcher::class));
    }
}
