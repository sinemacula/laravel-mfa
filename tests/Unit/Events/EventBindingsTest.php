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
 * Unit tests for `EventBindings`: the default event context resolver and the
 * dispatcher, each one instance per container.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(EventBindings::class)]
final class EventBindingsTest extends TestCase
{
    /**
     * The default resolver and the dispatcher are shared.
     *
     * @return void
     */
    public function testRegistersTheResolverAndTheDispatcherAsShared(): void
    {
        $app = $this->container();

        $app->forgetInstance(EventContextResolver::class);
        $app->forgetInstance(EventDispatcher::class);

        EventBindings::register($app);

        self::assertInstanceOf(DefaultEventContextResolver::class, $app->make(EventContextResolver::class));
        self::assertSame($app->make(EventContextResolver::class), $app->make(EventContextResolver::class));
        self::assertSame($app->make(EventDispatcher::class), $app->make(EventDispatcher::class));
    }
}
