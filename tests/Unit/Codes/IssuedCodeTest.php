<?php

declare(strict_types = 1);

namespace Tests\Unit\Codes;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Codes\IssuedCode;

/**
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(IssuedCode::class)]
final class IssuedCodeTest extends TestCase
{
    /**
     * @return void
     */
    public function testHoldsTheChallengeCodeAndExpiry(): void
    {
        $expiresAt = CarbonImmutable::parse('2026-11-01 12:10:00');

        $issued = new IssuedCode('challenge-1', '123456', $expiresAt);

        self::assertSame('challenge-1', $issued->challengeId);
        self::assertSame('123456', $issued->code);
        self::assertSame($expiresAt, $issued->expiresAt);
    }

    /**
     * @return void
     */
    public function testKeepsTheCodeOutOfAStackTrace(): void
    {
        $parameter = new \ReflectionParameter([IssuedCode::class, '__construct'], 'code');

        self::assertNotEmpty($parameter->getAttributes(\SensitiveParameter::class));
    }
}
