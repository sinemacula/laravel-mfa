<?php

declare(strict_types = 1);

namespace Tests\Unit\Drivers;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Drivers\PasskeyDriver;
use SineMacula\Laravel\Mfa\Enums\ChannelKind;
use SineMacula\Laravel\Mfa\Enums\CodeCheck;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
use Tests\Fixtures\Factors\InMemoryFactor;

/**
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PasskeyDriver::class)]
final class PasskeyDriverTest extends TestCase
{
    /**
     * @return void
     */
    public function testStatesItsChannelAndRefusesEveryCode(): void
    {
        $driver = new PasskeyDriver;
        $factor = new InMemoryFactor(type: 'passkey');

        self::assertSame(ChannelKind::PASSKEY, $driver->channelKind());
        self::assertSame([], $driver->amr());
        self::assertNull($driver->startEnrollment($factor));
        self::assertSame(CodeCheck::INVALID, $driver->confirm($factor, '123456', new ProofBinding('user', '1', 'web', 'sign-in-1', Purpose::ENROLLMENT)));
        self::assertSame(CodeCheck::INVALID, $driver->verify($factor, '123456', new ProofBinding('user', '1', 'web', 'sign-in-1', Purpose::STEP_UP)));
    }
}
