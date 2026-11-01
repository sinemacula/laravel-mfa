<?php

declare(strict_types = 1);

namespace Tests\Unit\Applications;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Applications\DeclaredFirstFactor;
use SineMacula\Laravel\Mfa\Enums\ChannelKind;

/**
 * Unit tests for `DeclaredFirstFactor`: it holds a method and a known channel
 * kind, and refuses a blank method or an unknown channel.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DeclaredFirstFactor::class)]
final class DeclaredFirstFactorTest extends TestCase
{
    /**
     * The declaration holds what it is given.
     *
     * @return void
     */
    public function testHoldsTheMethodAndChannel(): void
    {
        $declared = new DeclaredFirstFactor('password', ChannelKind::PASSWORD);

        self::assertSame('password', $declared->method);
        self::assertSame(ChannelKind::PASSWORD, $declared->channel);
    }

    /**
     * A blank method is refused.
     *
     * @return void
     */
    public function testRefusesABlankMethod(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('The method of a declared first factor must not be blank.');

        $declare = static fn (): DeclaredFirstFactor => new DeclaredFirstFactor(' ', ChannelKind::PASSWORD);
        $declare();
    }

    /**
     * An unknown channel is no declaration at all, and is refused.
     *
     * @return void
     */
    public function testRefusesAnUnknownChannel(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('The channel of a declared first factor must be known.');

        $declare = static fn (): DeclaredFirstFactor => new DeclaredFirstFactor('password', ChannelKind::UNKNOWN);
        $declare();
    }
}
