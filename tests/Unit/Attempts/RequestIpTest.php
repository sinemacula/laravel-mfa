<?php

declare(strict_types = 1);

namespace Tests\Unit\Attempts;

use Illuminate\Container\Container;
use Illuminate\Http\Request;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Attempts\RequestIp;

/**
 * Unit tests for `RequestIp`: the address of the request being served, and none
 * outside a request.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RequestIp::class)]
final class RequestIpTest extends TestCase
{
    /**
     * The address of the bound request.
     *
     * @return void
     */
    public function testTheAddressOfTheRequest(): void
    {
        $container = new Container;

        $container->instance('request', Request::create('/', server: ['REMOTE_ADDR' => '198.51.100.4']));

        self::assertSame('198.51.100.4', RequestIp::resolve($container));
    }

    /**
     * No address without a request, or with something else bound as one.
     *
     * @return void
     */
    public function testNoAddressOutsideARequest(): void
    {
        $container = new Container;

        self::assertNull(RequestIp::resolve($container));

        $container->instance('request', new \stdClass);

        self::assertNull(RequestIp::resolve($container));
    }
}
