<?php

declare(strict_types = 1);

namespace Tests\Unit\Exceptions;

use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Exceptions\MfaExpiredException;
use SineMacula\Laravel\Mfa\Support\FactorSummary;
use Symfony\Component\HttpKernel\Exception\HttpException;

/**
 * Unit tests for the `MfaExpiredException` exception.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 *
 * @internal
 */
final class MfaExpiredExceptionTest extends TestCase
{
    public function testIsFinal(): void
    {
        $reflection = new \ReflectionClass(MfaExpiredException::class);

        self::assertTrue($reflection->isFinal());
    }

    public function testExtendsHttpException(): void
    {
        self::assertInstanceOf(HttpException::class, new MfaExpiredException);
    }

    public function testDefaultStatusAndMessage(): void
    {
        $exception = new MfaExpiredException;

        self::assertSame(401, $exception->getStatusCode());
        self::assertSame('Multi-factor authentication has expired.', $exception->getMessage());
        self::assertSame([], $exception->getFactors());
    }

    public function testCustomMessageIsRespected(): void
    {
        $exception = new MfaExpiredException([], 'Please re-verify.');

        self::assertSame('Please re-verify.', $exception->getMessage());
    }

    public function testFactorsArePreserved(): void
    {
        $summary = new FactorSummary(
            id: '01HABCDEF',
            driver: 'email',
            label: 'Work email',
            maskedRecipient: 'al***@example.com',
            verifiedAt: null,
        );

        $exception = new MfaExpiredException([$summary]);

        self::assertSame([$summary], $exception->getFactors());
    }
}
