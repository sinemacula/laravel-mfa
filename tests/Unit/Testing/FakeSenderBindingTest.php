<?php

declare(strict_types = 1);

namespace Tests\Unit\Testing;

use Illuminate\Container\Container;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Contracts\EmailSender;
use SineMacula\Laravel\Mfa\Contracts\SmsSender;
use SineMacula\Laravel\Mfa\MfaManager;
use SineMacula\Laravel\Mfa\Testing\FakeEmailSender;
use SineMacula\Laravel\Mfa\Testing\FakeSenderBinding;
use SineMacula\Laravel\Mfa\Testing\FakeSmsSender;
use Tests\TestCase;

/**
 * Tests for `FakeSenderBinding`: a fake bound after the manager has built its
 * drivers is still the one they send through, and binding one builds no manager
 * that was not built already.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FakeSenderBinding::class)]
final class FakeSenderBindingTest extends TestCase
{
    /**
     * A code driver built before the fake is built again with it.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testADriverBuiltBeforeTheFakeIsBuiltAgain(): void
    {
        $manager = $this->container()->make('mfa');

        self::assertInstanceOf(MfaManager::class, $manager);

        $email = $manager->driver('email');

        FakeEmailSender::fake($this->container());

        self::assertNotSame($email, $manager->driver('email'));

        $sms = $manager->driver('sms');

        FakeSmsSender::fake($this->container());

        self::assertNotSame($sms, $manager->driver('sms'));
    }

    /**
     * Binding a fake builds no manager, and leaves alone anything else bound
     * under the manager's name.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testBindingAFakeBuildsNoManager(): void
    {
        $container = new Container;
        $fake      = new FakeSmsSender;

        FakeSenderBinding::bind($container, SmsSender::class, $fake);

        self::assertSame($fake, $container->make(SmsSender::class));
        self::assertFalse($container->resolved('mfa'));

        $other = new \stdClass;

        $container->instance('mfa', $other);

        FakeSenderBinding::bind($container, EmailSender::class, new FakeEmailSender);

        self::assertSame($other, $container->make('mfa'));
    }
}
