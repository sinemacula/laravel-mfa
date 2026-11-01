<?php

declare(strict_types = 1);

namespace Tests\Unit\Exceptions;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Enums\FactorStatus;
use SineMacula\Laravel\Mfa\Exceptions\CodeDeliveryFailedException;
use SineMacula\Laravel\Mfa\Factors\FactorSummary;

/**
 * Unit tests for `CodeDeliveryFailedException`: a runtime failure naming the
 * factor's type and masked destination, over the delivery's own failure.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CodeDeliveryFailedException::class)]
final class CodeDeliveryFailedExceptionTest extends TestCase
{
    /**
     * The exception names the factor's type and masked destination, carries the
     * summary, and keeps the delivery's failure as its previous one.
     *
     * @return void
     */
    public function testTheExceptionNamesTheFactorMasked(): void
    {
        $failure   = new \RuntimeException('The gateway refused the message.');
        $summary   = $this->summary('*********0123');
        $exception = new CodeDeliveryFailedException($summary, $failure);

        self::assertInstanceOf(\RuntimeException::class, $exception);
        self::assertSame('The code could not be delivered to the sms factor at *********0123.', $exception->getMessage());
        self::assertSame($summary, $exception->factor);
        self::assertSame($failure, $exception->getPrevious());
        self::assertSame(0, $exception->getCode());
    }

    /**
     * A factor without a destination is named by its type alone.
     *
     * @return void
     */
    public function testAFactorWithoutADestinationIsNamedByItsType(): void
    {
        $exception = new CodeDeliveryFailedException($this->summary(null), new \RuntimeException('Failed.'));

        self::assertSame('The code could not be delivered to the sms factor.', $exception->getMessage());
    }

    /**
     * A summary of an SMS factor with the masked destination.
     *
     * @param  ?string  $maskedDestination
     * @return \SineMacula\Laravel\Mfa\Factors\FactorSummary
     */
    private function summary(?string $maskedDestination): FactorSummary
    {
        return new FactorSummary('01J0', 'sms', null, $maskedDestination, FactorStatus::CONFIRMED, false, null);
    }
}
