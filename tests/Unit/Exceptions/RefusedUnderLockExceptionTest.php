<?php

declare(strict_types = 1);

namespace Tests\Unit\Exceptions;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException;
use SineMacula\Laravel\Mfa\Exceptions\RefusedUnderLockException;

/**
 * Unit tests for `RefusedUnderLockException`: it carries a refusal, and the
 * challenge reported before it, out of the transaction.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RefusedUnderLockException::class)]
final class RefusedUnderLockExceptionTest extends TestCase
{
    /**
     * A refusal thrown by the work is carried out with the challenge named, and
     * stays the exception's previous one.
     *
     * @return void
     */
    public function testARefusalIsCarriedOut(): void
    {
        $refusal = new OperationRefusedException(FailureReason::NOT_ACCEPTED, 'Refused.');

        $caught = null;

        try {
            RefusedUnderLockException::carrying(static function () use ($refusal): void {
                throw $refusal;
            }, 'challenge-1');
        } catch (RefusedUnderLockException $exception) {
            $caught = $exception;
        }

        self::assertInstanceOf(RefusedUnderLockException::class, $caught);
        self::assertSame($refusal, $caught->refusal);
        self::assertSame($refusal, $caught->getPrevious());
        self::assertSame('challenge-1', $caught->challengeId);
        self::assertSame('The operation was refused under the identity\'s lock.', $caught->getMessage());
        self::assertSame(0, $caught->getCode());
    }

    /**
     * Work that is not refused answers as it did, and anything else it throws
     * is left alone.
     *
     * @return void
     */
    public function testAnythingElseIsLeftAlone(): void
    {
        self::assertSame('done', RefusedUnderLockException::carrying(static fn (): string => 'done'));

        $this->expectException(\LogicException::class);

        RefusedUnderLockException::carrying(static function (): void {
            throw new \LogicException('Not a refusal.');
        });
    }
}
