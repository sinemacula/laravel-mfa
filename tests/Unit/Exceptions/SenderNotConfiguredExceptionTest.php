<?php

declare(strict_types = 1);

namespace Tests\Unit\Exceptions;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Contracts\SmsSender;
use SineMacula\Laravel\Mfa\Exceptions\SenderNotConfiguredException;

/**
 * Unit tests for `SenderNotConfiguredException`: a runtime failure naming the
 * contract to bind.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SenderNotConfiguredException::class)]
final class SenderNotConfiguredExceptionTest extends TestCase
{
    /**
     * The exception is a runtime failure naming the contract.
     *
     * @return void
     */
    public function testTheExceptionNamesTheContractToBind(): void
    {
        $exception = SenderNotConfiguredException::for(SmsSender::class);

        self::assertInstanceOf(\RuntimeException::class, $exception);
        self::assertSame(sprintf('No sender is bound to deliver codes: bind an implementation of %s in a service provider.', SmsSender::class), $exception->getMessage());
    }
}
