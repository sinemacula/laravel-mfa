<?php

declare(strict_types = 1);

namespace Tests\Unit\Enums;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Enums\ChannelKind;

/**
 * Unit tests for the `ChannelKind` enum: its stable values, and which kinds
 * name a destination or credential.
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
     * The channel kinds, in order, with their stable values.
     *
     * @return void
     */
    public function testChannelKindsAreTheStableValues(): void
    {
        self::assertSame([
            'password',
            'sms',
            'email',
            'authenticator_app',
            'passkey',
            'external_provider',
            'unknown',
        ], array_map(static fn (ChannelKind $kind): string => $kind->value, ChannelKind::cases()));
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
}
