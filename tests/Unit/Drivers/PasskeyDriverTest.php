<?php

declare(strict_types = 1);

namespace Tests\Unit\Drivers;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Drivers\PasskeyDriver;
use SineMacula\Laravel\Mfa\Enums\ChannelKind;
use Tests\Fixtures\Factors\InMemoryFactor;

/**
 * Unit tests for `PasskeyDriver`: a passkey travels on a passkey channel,
 * claims no `amr` value of its own, has no secret, and is never confirmed or
 * proved by a code.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PasskeyDriver::class)]
final class PasskeyDriverTest extends TestCase
{
    /**
     * The driver's answers.
     *
     * @return void
     */
    public function testStatesItsChannelAndRefusesEveryCode(): void
    {
        $driver = new PasskeyDriver;
        $factor = new InMemoryFactor(type: 'passkey');

        $driver->issueChallenge($factor);

        self::assertSame(ChannelKind::PASSKEY, $driver->channelKind());
        self::assertSame([], $driver->amr());
        self::assertNull($driver->startEnrollment($factor));
        self::assertFalse($driver->confirm($factor, '123456'));
        self::assertFalse($driver->verify($factor, '123456'));
    }
}
