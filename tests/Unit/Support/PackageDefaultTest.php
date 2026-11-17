<?php

declare(strict_types = 1);

namespace Tests\Unit\Support;

use Illuminate\Container\Container;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Codes\NullSmsSender;
use SineMacula\Laravel\Mfa\Contracts\SmsSender;
use SineMacula\Laravel\Mfa\Support\PackageDefault;
use SineMacula\Laravel\Mfa\Testing\FakeSmsSender;

/**
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PackageDefault::class)]
final class PackageDefaultTest extends TestCase
{
    /**
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testResolvesAFreshInstanceOfTheClass(): void
    {
        $container = new Container;

        PackageDefault::bind($container, SmsSender::class, NullSmsSender::class);

        $first = $container->make(SmsSender::class);

        self::assertInstanceOf(NullSmsSender::class, $first);
        self::assertNotSame($first, $container->make(SmsSender::class));
    }

    /**
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testFollowsABindingOfTheClass(): void
    {
        $container = new Container;

        PackageDefault::bind($container, SmsSender::class, NullSmsSender::class);

        $container->bind(NullSmsSender::class, FakeSmsSender::class);

        self::assertInstanceOf(FakeSmsSender::class, $container->make(SmsSender::class));
    }

    /**
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testPassesTheParametersToTheClass(): void
    {
        $container = new Container;

        PackageDefault::bind($container, 'contract', \ArrayObject::class);

        $made = $container->make('contract', ['array' => ['given']]);

        self::assertInstanceOf(\ArrayObject::class, $made);
        self::assertSame(['given'], $made->getArrayCopy());
    }

    /**
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testKeepsABindingAlreadyMade(): void
    {
        $container = new Container;

        $container->bind(SmsSender::class, FakeSmsSender::class);

        PackageDefault::bind($container, SmsSender::class, NullSmsSender::class);

        self::assertInstanceOf(FakeSmsSender::class, $container->make(SmsSender::class));
    }

    /**
     * Once for the contract, as for a class bound by name.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testRaisesTheClassResolvingCallbacksOnce(): void
    {
        $container = new Container;
        $raised    = 0;

        PackageDefault::bind($container, SmsSender::class, NullSmsSender::class);

        $container->resolving(NullSmsSender::class, static function () use (&$raised): void {
            $raised++;
        });

        $container->make(SmsSender::class);

        self::assertSame(1, $raised);
    }
}
