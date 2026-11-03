<?php

declare(strict_types = 1);

namespace Tests\Unit\Factors;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Enums\ChannelKind;
use SineMacula\Laravel\Mfa\Factors\FactorChannel;
use SineMacula\Laravel\Mfa\Models\Factor;
use Tests\Fixtures\Factors\InMemoryFactor;
use Tests\TestCase;

/**
 * Unit tests for `FactorChannel`: a factor's channel names its destination, its
 * passkey credential, or the factor itself, and a kind that cannot carry a
 * factor, or an identifier that cannot name one, has none.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FactorChannel::class)]
final class FactorChannelTest extends TestCase
{
    /**
     * The channel names the destination first, then the credential, then the
     * factor.
     *
     * @return void
     */
    public function testNamesTheDestinationThenTheCredentialThenTheFactor(): void
    {
        $passkey = new Factor(['type' => 'passkey', 'credential_reference' => 'Y3JlZGVudGlhbC1vbmU']);

        $passkey->setAttribute('id', 'factor-passkey');

        $channel = FactorChannel::of($passkey, ChannelKind::PASSKEY);

        self::assertSame('person@example.test', FactorChannel::of(new InMemoryFactor(type: 'email', destination: 'person@example.test'), ChannelKind::EMAIL)?->reference());

        self::assertNotNull($channel);
        self::assertSame('Y3JlZGVudGlhbC1vbmU', $channel->reference());
        self::assertSame(ChannelKind::PASSKEY, $channel->kind);

        $both = new Factor(['type' => 'email', 'destination' => 'person@example.test', 'credential_reference' => 'Y3JlZGVudGlhbC1vbmU']);

        $both->setAttribute('id', 'factor-both');

        self::assertSame('person@example.test', FactorChannel::of($both, ChannelKind::EMAIL)?->reference());

        self::assertSame('factor-id', FactorChannel::of(new InMemoryFactor, ChannelKind::AUTHENTICATOR_APP)?->reference());
        self::assertSame('7', FactorChannel::of(new InMemoryFactor(identifier: 7), ChannelKind::AUTHENTICATOR_APP)?->reference());
    }

    /**
     * A kind that cannot carry a factor, or a factor that cannot be named, has
     * no channel.
     *
     * @return void
     */
    public function testHasNoChannelItCannotName(): void
    {
        self::assertNull(FactorChannel::of(new InMemoryFactor, ChannelKind::PASSWORD));
        self::assertNull(FactorChannel::of(new InMemoryFactor(identifier: null), ChannelKind::AUTHENTICATOR_APP));
    }
}
