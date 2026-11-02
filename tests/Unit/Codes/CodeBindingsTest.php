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
 * binds its own, the code service is built afresh, and the engine is built
 * afresh each time it is resolved.
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
     * built afresh.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testBindsTheNullSendersAfreshOnEveryResolution(): void
    {
        self::assertInstanceOf(NullSmsSender::class, $this->container()->make(SmsSender::class));
        self::assertInstanceOf(NullEmailSender::class, $this->container()->make(EmailSender::class));
        self::assertFalse($this->container()->isShared(SmsSender::class));
        self::assertFalse($this->container()->isShared(EmailSender::class));
    }

    /**
     * The code service is built afresh, and the engine, which reads the
     * configuration on every call, is built afresh.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testRegistersTheServiceAndTheEngine(): void
    {
        self::assertTrue($this->container()->bound(CodeService::class));
        self::assertNotSame($this->container()->make(CodeService::class), $this->container()->make(CodeService::class));
        self::assertInstanceOf(DeliveredCodes::class, $this->container()->make(DeliveredCodes::class));
        self::assertNotSame($this->container()->make(DeliveredCodes::class), $this->container()->make(DeliveredCodes::class));
    }

    /**
     * The challenge gateway defaults to the package's own codes, built afresh.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testBindsThePackagesOwnChallengeGatewayByDefault(): void
    {
        self::assertInstanceOf(PackageChallengeGateway::class, $this->container()->make(ChallengeGateway::class));
        self::assertFalse($this->container()->isShared(ChallengeGateway::class));
    }
}
