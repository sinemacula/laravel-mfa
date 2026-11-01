<?php

declare(strict_types = 1);

namespace Tests\Unit\Exceptions;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Enums\FactorStatus;
use SineMacula\Laravel\Mfa\Exceptions\AbstractMfaHttpException;
use SineMacula\Laravel\Mfa\Exceptions\MfaExpiredException;
use SineMacula\Laravel\Mfa\Factors\FactorSummary;
use Symfony\Component\HttpKernel\Exception\HttpException;

/**
 * Unit tests for the `MfaExpiredException` exception.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AbstractMfaHttpException::class)]
#[CoversClass(MfaExpiredException::class)]
final class MfaExpiredExceptionTest extends TestCase
{
    /**
     * Test is final.
     *
     * @return void
     */
    public function testIsFinal(): void
    {
        $reflection = new \ReflectionClass(MfaExpiredException::class);

        self::assertTrue($reflection->isFinal());
    }

    /**
     * Test extends http exception.
     *
     * @return void
     */
    public function testExtendsHttpException(): void
    {
        self::assertInstanceOf(HttpException::class, new MfaExpiredException);
    }

    /**
     * Test default status and message.
     *
     * @return void
     */
    public function testDefaultStatusAndMessage(): void
    {
        $exception = new MfaExpiredException;

        self::assertSame(401, $exception->getStatusCode());
        self::assertSame('Multi-factor authentication has expired.', $exception->getMessage());
        self::assertSame([], $exception->getFactors());
    }

    /**
     * Test custom message is respected.
     *
     * @return void
     */
    public function testCustomMessageIsRespected(): void
    {
        $exception = new MfaExpiredException([], 'Please re-verify.');

        self::assertSame('Please re-verify.', $exception->getMessage());
    }

    /**
     * Test factors are preserved.
     *
     * @return void
     */
    public function testFactorsArePreserved(): void
    {
        $summary = new FactorSummary(
            id             : '01HABCDEF',
            type         : 'email',
            label          : 'Work email',
            maskedDestination: 'al***@example.com',
            status     : FactorStatus::CONFIRMED,
            preferred: false,
            lastUsedAt: null,
        );

        $exception = new MfaExpiredException([$summary]);

        self::assertSame([$summary], $exception->getFactors());
    }
}
