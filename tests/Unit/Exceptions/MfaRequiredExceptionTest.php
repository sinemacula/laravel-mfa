<?php

declare(strict_types = 1);

namespace Tests\Unit\Exceptions;

use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Exceptions\MfaRequiredException;
use SineMacula\Laravel\Mfa\Support\FactorSummary;
use Symfony\Component\HttpKernel\Exception\HttpException;

/**
 * Unit tests for the `MfaRequiredException` exception.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 *
 * @internal
 */
final class MfaRequiredExceptionTest extends TestCase
{
    public function testIsFinal(): void
    {
        $reflection = new \ReflectionClass(MfaRequiredException::class);

        self::assertTrue($reflection->isFinal());
    }

    public function testExtendsHttpException(): void
    {
        self::assertInstanceOf(HttpException::class, new MfaRequiredException);
    }

    public function testDefaultStatusAndMessage(): void
    {
        $exception = new MfaRequiredException;

        self::assertSame(401, $exception->getStatusCode());
        self::assertSame('Multi-factor authentication is required.', $exception->getMessage());
        self::assertSame([], $exception->getFactors());
    }

    public function testCustomMessageIsRespected(): void
    {
        $exception = new MfaRequiredException([], 'Please verify.');

        self::assertSame('Please verify.', $exception->getMessage());
    }

    public function testFactorsArePreserved(): void
    {
        $summary = new FactorSummary(
            id: '01HABCDEF',
            driver: 'totp',
            label: 'Phone',
            maskedRecipient: null,
            verifiedAt: null,
        );

        $exception = new MfaRequiredException([$summary]);

        self::assertSame([$summary], $exception->getFactors());
    }
}
