<?php

declare(strict_types = 1);

namespace Tests\Unit\Codes;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Codes\CodeBindings;
use SineMacula\Laravel\Mfa\Codes\NullSmsGateway;
use SineMacula\Laravel\Mfa\Contracts\SmsGateway;
use Tests\TestCase;

/**
 * Tests for `CodeBindings`: the default SMS gateway fails loud until the
 * application binds its own.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CodeBindings::class)]
final class CodeBindingsTest extends TestCase
{
    /**
     * The default SMS gateway is the one that fails loud, and is shared.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testBindsTheNullGatewayAsASingleton(): void
    {
        self::assertInstanceOf(NullSmsGateway::class, $this->container()->make(SmsGateway::class));
        self::assertSame($this->container()->make(SmsGateway::class), $this->container()->make(SmsGateway::class));
    }
}
