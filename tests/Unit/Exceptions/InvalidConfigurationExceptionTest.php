<?php

declare(strict_types = 1);

namespace Tests\Unit\Exceptions;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Exceptions\InvalidConfigurationException;

/**
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(InvalidConfigurationException::class)]
final class InvalidConfigurationExceptionTest extends TestCase
{
    /**
     * @return void
     */
    public function testListsEveryProblem(): void
    {
        $problems  = ['[codes] mfa.codes.length must be an integer from 6 to 10.', '[totp] mfa.totp.window must be an integer from 0 to 3.'];
        $exception = new InvalidConfigurationException($problems);

        self::assertSame($problems, $exception->problems);
        self::assertSame("The MFA configuration is invalid:\n" . implode("\n", $problems), $exception->getMessage());
        self::assertInstanceOf(\LogicException::class, $exception);
    }
}
