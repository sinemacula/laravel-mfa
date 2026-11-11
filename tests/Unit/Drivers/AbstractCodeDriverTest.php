<?php

declare(strict_types = 1);

namespace Tests\Unit\Drivers;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Drivers\AbstractCodeDriver;
use SineMacula\Laravel\Mfa\Enums\CodeCheck;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
use Tests\Fixtures\Codes\CodeMessages;
use Tests\Fixtures\Codes\RecordingCodeDriver;
use Tests\Fixtures\Factors\InMemoryFactor;

/**
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AbstractCodeDriver::class)]
final class AbstractCodeDriverTest extends TestCase
{
    /**
     * @return void
     */
    public function testADeliveredCodeAddsOtpAndKeepsNoSecret(): void
    {
        $driver = new RecordingCodeDriver;

        self::assertSame(['otp'], $driver->amr());
        self::assertNull($driver->startEnrollment(new InMemoryFactor(type: 'email')));
    }

    /**
     * The call, and the word naming what it would do.
     *
     * @return iterable<string, array{\Closure(\Tests\Fixtures\Codes\RecordingCodeDriver): mixed, string}>
     */
    public static function unboundCalls(): iterable
    {
        $factor = new InMemoryFactor(type: 'email', destination: 'ada@example.test');

        $binding = new ProofBinding('user', '1', 'web', 'sign-in-1', Purpose::STEP_UP);

        yield 'confirm' => [static fn (RecordingCodeDriver $driver): CodeCheck => $driver->confirm($factor, '123456', $binding), 'confirmed'];

        yield 'verify' => [static fn (RecordingCodeDriver $driver): CodeCheck => $driver->verify($factor, '123456', $binding), 'checked'];
    }

    /**
     * A code is bound to more than its factor.
     *
     * @param  \Closure(\Tests\Fixtures\Codes\RecordingCodeDriver): mixed  $call
     * @param  string  $action
     * @return void
     */
    #[DataProvider('unboundCalls')]
    public function testAFactorOnlyCallIsRefused(\Closure $call, string $action): void
    {
        $driver = new RecordingCodeDriver;

        try {
            $call($driver);
            self::fail('Expected the call to be refused.');
        } catch (\LogicException $exception) {
            $message = 'A delivered code is bound to its factor, session, application and purpose, so it is %s through the code service, never by the driver alone.';

            self::assertSame(sprintf($message, $action), $exception->getMessage());
        }

        self::assertSame([], $driver->delivered);
    }

    /**
     * @return void
     */
    public function testDeliveryHandsTheMessageToTheTransport(): void
    {
        $driver  = new RecordingCodeDriver;
        $message = CodeMessages::to('ada@example.test');

        $driver->deliver(new InMemoryFactor(type: 'email', destination: 'ada@example.test'), $message);

        self::assertCount(1, $driver->delivered);
        self::assertSame($message, $driver->delivered[0]['message']);
        self::assertSame('ada@example.test', $driver->delivered[0]['destination']);
        self::assertSame('123456', $driver->delivered[0]['code']);
    }
}
