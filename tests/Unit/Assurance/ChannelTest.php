<?php

declare(strict_types = 1);

namespace Tests\Unit\Assurance;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Assurance\Channel;
use SineMacula\Laravel\Mfa\Enums\ChannelKind;
use Tests\Fixtures\Verification\Dumps;

/**
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Channel::class)]
final class ChannelTest extends TestCase
{
    /**
     * @return void
     */
    public function testAChannelKeepsItsKindAndReference(): void
    {
        $channel = new Channel(ChannelKind::SMS, '+447700900123');

        self::assertSame(ChannelKind::SMS, $channel->kind);
        self::assertSame('+447700900123', $channel->reference());
    }

    /**
     * PHP refuses to serialise one; only `toArray()` gives it up, for storing a
     * proof.
     *
     * @return void
     */
    public function testNoDumpShowsTheReference(): void
    {
        $channel = new Channel(ChannelKind::SMS, '+447700900123');

        foreach (Dumps::of($channel) as $way => $shown) {
            self::assertStringNotContainsString('+447700900123', $shown, $way);
            self::assertStringContainsStringIgnoringCase('sms', $shown, $way);
        }

        $this->expectException(\Exception::class);
        $this->expectExceptionMessage('Serialization of \'SensitiveParameterValue\' is not allowed');

        serialize($channel);
    }

    /**
     * @return void
     */
    public function testAReferenceIsOptional(): void
    {
        self::assertNull((new Channel(ChannelKind::PASSWORD))->reference());
        self::assertNull((new Channel(ChannelKind::PASSKEY))->reference());
    }

    /**
     * Of the unknown kind, naming nothing.
     *
     * @return void
     */
    public function testTheUnknownChannel(): void
    {
        $channel = Channel::unknown();

        self::assertSame(ChannelKind::UNKNOWN, $channel->kind);
        self::assertNull($channel->reference());
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideBlankReferences(): iterable
    {
        yield 'empty' => [''];
        yield 'spaces' => ['   '];
        yield 'a tab' => ["\t"];
    }

    /**
     * @param  string  $reference
     * @return void
     */
    #[DataProvider('provideBlankReferences')]
    public function testABlankReferenceIsRefused(string $reference): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('A channel reference must not be blank.');

        new Channel(ChannelKind::EMAIL, $reference);
    }

    /**
     * @return iterable<string, array{\SineMacula\Laravel\Mfa\Enums\ChannelKind}>
     */
    public static function provideKindsWithoutAReference(): iterable
    {
        yield 'password' => [ChannelKind::PASSWORD];
        yield 'unknown' => [ChannelKind::UNKNOWN];
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Enums\ChannelKind  $kind
     * @return void
     */
    #[DataProvider('provideKindsWithoutAReference')]
    public function testAKindThatNamesNothingRefusesAReference(ChannelKind $kind): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage(sprintf('A channel of kind [%s] takes no reference.', $kind->value));

        new Channel($kind, 'reference');
    }

    /**
     * Snake_case keys and the kind's value.
     *
     * @return void
     */
    public function testTheSerializedForm(): void
    {
        $channel = new Channel(ChannelKind::AUTHENTICATOR_APP, '01J0000000000000000000000A');

        $expected = ['kind' => 'authenticator_app', 'reference' => '01J0000000000000000000000A'];

        self::assertSame($expected, $channel->toArray());
        self::assertSame($expected, $channel->jsonSerialize());
        self::assertSame('{"kind":"password","reference":null}', json_encode(new Channel(ChannelKind::PASSWORD)));
    }

    /**
     * @return void
     */
    public function testAChannelRoundTrips(): void
    {
        $channel = new Channel(ChannelKind::EXTERNAL_PROVIDER, 'okta');

        self::assertSame($channel->toArray(), Channel::fromArray($channel->toArray())->toArray());
        self::assertEquals(Channel::unknown(), Channel::fromArray(['kind' => 'unknown']));
    }

    /**
     * @return iterable<string, array{array<string, mixed>, string}>
     */
    public static function provideMalformedChannels(): iterable
    {
        yield 'no kind' => [[], 'The [kind] field of a serialised channel must be a string.'];
        yield 'a kind that is not a string' => [['kind' => 1], 'The [kind] field of a serialised channel must be a string.'];
        yield 'an unknown kind' => [['kind' => 'carrier_pigeon'], 'The [kind] field of a serialised channel is not a known value.'];
        yield 'a reference that is not a string' => [['kind' => 'sms', 'reference' => 7], 'The [reference] field of a serialised channel must be a string or null.'];
        yield 'a blank reference' => [['kind' => 'sms', 'reference' => ''], 'A channel reference must not be blank.'];
        yield 'an unknown field' => [['kind' => 'sms', 'destination' => '+447700900123'], 'The [destination] field of a serialised channel is not a known field.'];
    }

    /**
     * @param  array<string, mixed>  $data
     * @param  string  $message
     * @return void
     */
    #[DataProvider('provideMalformedChannels')]
    public function testAMalformedChannelIsRefused(array $data, string $message): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage($message);

        Channel::fromArray($data);
    }
}
