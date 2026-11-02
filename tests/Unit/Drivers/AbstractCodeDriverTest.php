<?php

declare(strict_types = 1);

namespace Tests\Unit\Drivers;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Drivers\AbstractCodeDriver;
use SineMacula\Laravel\Mfa\Enums\CodeCheck;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Exceptions\MissingDestinationException;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
use Tests\Fixtures\Codes\RecordingCodeDriver;
use Tests\Fixtures\Factors\InMemoryFactor;

/**
 * Unit tests for `AbstractCodeDriver`: what a delivered-code driver states, its
 * refusal of every call that would send or accept a code bound to nothing, and
 * the destination guard in front of its transport.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AbstractCodeDriver::class)]
final class AbstractCodeDriverTest extends TestCase
{
    /**
     * A delivered code adds `otp` and keeps no secret to start an enrolment
     * with.
     *
     * @return void
     */
    public function testADeliveredCodeAddsOtpAndKeepsNoSecret(): void
    {
        $driver = new RecordingCodeDriver;

        self::assertSame(['otp'], $driver->amr());
        self::assertNull($driver->startEnrollment(new InMemoryFactor(type: 'email')));
    }

    /**
     * Rows of `[the call, the word naming what it would do]`.
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
     * Checking or confirming a code with the factor alone is refused, and
     * delivers nothing: a code is bound to more than its factor.
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
     * The code reaches the transport with the factor's destination and its
     * expiry.
     *
     * @return void
     */
    public function testDeliveryHandsTheCodeToTheTransport(): void
    {
        $driver    = new RecordingCodeDriver;
        $expiresAt = CarbonImmutable::now()->addMinutes(10);

        $driver->deliver(new InMemoryFactor(type: 'email', destination: 'ada@example.test'), '123456', $expiresAt);

        self::assertSame([['destination' => 'ada@example.test', 'code' => '123456', 'expires_at' => $expiresAt]], $driver->delivered);
    }

    /**
     * Rows of a destination a code cannot be delivered to.
     *
     * @return iterable<string, array{?string}>
     */
    public static function missingDestinations(): iterable
    {
        yield 'none' => [null];
        yield 'empty' => [''];
    }

    /**
     * A factor with no destination is refused, naming its type, before the
     * transport is reached.
     *
     * @param  ?string  $destination
     * @return void
     */
    #[DataProvider('missingDestinations')]
    public function testAFactorWithoutADestinationIsRefused(?string $destination): void
    {
        $driver = new RecordingCodeDriver;

        try {
            $driver->deliver(new InMemoryFactor(type: 'sms', destination: $destination), '123456', CarbonImmutable::now());
            self::fail('Expected the delivery to be refused.');
        } catch (MissingDestinationException $exception) {
            self::assertSame('The sms factor has no destination, so its code cannot be delivered.', $exception->getMessage());
        }

        self::assertSame([], $driver->delivered);
    }
}
