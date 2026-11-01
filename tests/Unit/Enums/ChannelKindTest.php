<?php

declare(strict_types = 1);

namespace Tests\Unit\Enums;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Enums\ChannelKind;

/**
 * Unit tests for the `ChannelKind` enum: its stable values, which kinds name a
 * destination or credential, and which carry an enrolled factor.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ChannelKind::class)]
final class ChannelKindTest extends TestCase
{
    /**
     * The channel kinds, in order, each case name with its stable value.
     *
     * @return void
     */
    public function testChannelKindsAreTheStableValues(): void
    {
        self::assertSame([
            'PASSWORD'          => 'password',
            'SMS'               => 'sms',
            'EMAIL'             => 'email',
            'AUTHENTICATOR_APP' => 'authenticator_app',
            'PASSKEY'           => 'passkey',
            'EXTERNAL_PROVIDER' => 'external_provider',
            'UNKNOWN'           => 'unknown',
        ], array_column(ChannelKind::cases(), 'value', 'name'));
    }

    /**
     * Every kind but a password and an unknown channel names a destination or a
     * credential.
     *
     * @return void
     */
    public function testTheKindsThatTakeAReference(): void
    {
        $kinds = array_values(array_filter(ChannelKind::cases(), static fn (ChannelKind $kind): bool => $kind->takesReference()));

        self::assertSame([
            ChannelKind::SMS,
            ChannelKind::EMAIL,
            ChannelKind::AUTHENTICATOR_APP,
            ChannelKind::PASSKEY,
            ChannelKind::EXTERNAL_PROVIDER,
        ], $kinds);
    }

    /**
     * An enrolled factor travels on every kind but a password and an unknown
     * channel, which belong to first factors only.
     *
     * @return void
     */
    public function testTheKindsThatCarryAFactor(): void
    {
        $kinds = array_values(array_filter(ChannelKind::cases(), static fn (ChannelKind $kind): bool => $kind->carriesFactor()));

        self::assertSame([
            ChannelKind::SMS,
            ChannelKind::EMAIL,
            ChannelKind::AUTHENTICATOR_APP,
            ChannelKind::PASSKEY,
            ChannelKind::EXTERNAL_PROVIDER,
        ], $kinds);
    }
}
