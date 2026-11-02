<?php

declare(strict_types = 1);

namespace Tests\Unit\Codes;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Codes\CodeBindings;
use SineMacula\Laravel\Mfa\Codes\CodeService;
use SineMacula\Laravel\Mfa\Codes\DeliveredCodes;
use SineMacula\Laravel\Mfa\Codes\NullEmailSender;
use SineMacula\Laravel\Mfa\Codes\NullSmsSender;
use SineMacula\Laravel\Mfa\Codes\PackageChallengeGateway;
use SineMacula\Laravel\Mfa\Contracts\ChallengeGateway;
use SineMacula\Laravel\Mfa\Contracts\EmailSender;
use SineMacula\Laravel\Mfa\Contracts\SmsSender;
use Tests\TestCase;

/**
 * Tests for `CodeBindings`: the default senders fail loud until the application
 * binds its own, the code service is shared, and the engine is built afresh
 * each time it is resolved.
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
     * The default SMS and email senders are the ones that fail loud, and are
     * shared.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testBindsTheNullSendersAsSingletons(): void
    {
        self::assertInstanceOf(NullSmsSender::class, $this->container()->make(SmsSender::class));
        self::assertInstanceOf(NullEmailSender::class, $this->container()->make(EmailSender::class));
        self::assertTrue($this->container()->isShared(SmsSender::class));
        self::assertTrue($this->container()->isShared(EmailSender::class));
    }

    /**
     * The code service is shared, and the engine, which reads the configuration
     * on every call, is built afresh.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testRegistersTheServiceAndTheEngine(): void
    {
        self::assertSame($this->container()->make(CodeService::class), $this->container()->make(CodeService::class));
        self::assertInstanceOf(DeliveredCodes::class, $this->container()->make(DeliveredCodes::class));
        self::assertNotSame($this->container()->make(DeliveredCodes::class), $this->container()->make(DeliveredCodes::class));
    }

    /**
     * The challenge gateway defaults to the package's own codes, shared.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testBindsThePackagesOwnChallengeGatewayByDefault(): void
    {
        self::assertInstanceOf(PackageChallengeGateway::class, $this->container()->make(ChallengeGateway::class));
        self::assertTrue($this->container()->isShared(ChallengeGateway::class));
    }
}
