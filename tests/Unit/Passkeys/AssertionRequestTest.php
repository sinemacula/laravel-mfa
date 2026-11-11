<?php

declare(strict_types = 1);

namespace Tests\Unit\Passkeys;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Passkeys\AssertionRequest;

/**
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AssertionRequest::class)]
final class AssertionRequestTest extends TestCase
{
    /**
     * @return void
     */
    public function testStartedHoldsTheOptions(): void
    {
        $request = AssertionRequest::started(['challenge' => 'abc']);

        self::assertTrue($request->hasStarted());
        self::assertSame(['challenge' => 'abc'], $request->options);
        self::assertNull($request->reason);
    }

    /**
     * @return void
     */
    public function testRefusedHoldsTheReason(): void
    {
        $request = AssertionRequest::refused(FailureReason::NOT_ACCEPTED);

        self::assertFalse($request->hasStarted());
        self::assertSame([], $request->options);
        self::assertSame(FailureReason::NOT_ACCEPTED, $request->reason);
    }

    /**
     * @return void
     */
    public function testAnEmptyAnswerIsStillStarted(): void
    {
        self::assertTrue(AssertionRequest::started([])->hasStarted());
    }
}
