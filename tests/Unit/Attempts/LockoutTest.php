<?php

declare(strict_types = 1);

namespace Tests\Unit\Attempts;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Attempts\Lockout;
use SineMacula\Laravel\Mfa\Enums\AttemptScope;

/**
 * Unit tests for `Lockout`: a lockout that ends, a factor disabled at the
 * failure ceiling, the strictest of several, and the detail each reports.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Lockout::class)]
final class LockoutTest extends TestCase
{
    /**
     * A lockout that ends carries its scope and end, and is not a disabled
     * factor.
     *
     * @return void
     */
    public function testALockoutEndsAtItsTime(): void
    {
        $until   = CarbonImmutable::parse('2026-11-01 12:15:00');
        $lockout = Lockout::endingAt(AttemptScope::IDENTITY, $until);

        self::assertSame(AttemptScope::IDENTITY, $lockout->scope);
        self::assertSame($until, $lockout->until);
        self::assertFalse($lockout->isDisabled());
    }

    /**
     * A factor disabled at the failure ceiling has no end.
     *
     * @return void
     */
    public function testADisabledFactorHasNoEnd(): void
    {
        $lockout = Lockout::disabled();

        self::assertSame(AttemptScope::FACTOR, $lockout->scope);
        self::assertNull($lockout->until);
        self::assertTrue($lockout->isDisabled());
    }

    /**
     * Each lockout and the detail it reports.
     *
     * @return iterable<string, array{\SineMacula\Laravel\Mfa\Attempts\Lockout, string}>
     */
    public static function details(): iterable
    {
        $until = CarbonImmutable::parse('2026-11-01 12:15:00');

        yield 'a disabled factor' => [Lockout::disabled(), 'The factor is disabled after reaching the failure ceiling.'];
        yield 'a locked factor' => [Lockout::endingAt(AttemptScope::FACTOR, $until), 'The factor is locked after too many failed attempts.'];
        yield 'a locked identity' => [Lockout::endingAt(AttemptScope::IDENTITY, $until), 'The identity is locked after too many failed attempts across its factors.'];
        yield 'a throttled address' => [Lockout::endingAt(AttemptScope::IP, $until), 'The IP address is throttled after too many failed attempts.'];
    }

    /**
     * Each lockout reports what is refused and why.
     *
     * @param  \SineMacula\Laravel\Mfa\Attempts\Lockout  $lockout
     * @param  string  $detail
     * @return void
     */
    #[DataProvider('details')]
    public function testEachLockoutReportsItsDetail(Lockout $lockout, string $detail): void
    {
        self::assertSame($detail, $lockout->detail());
    }

    /**
     * The strictest of no lockout is none.
     *
     * @return void
     */
    public function testTheStrictestOfNoneIsNone(): void
    {
        self::assertNull(Lockout::strictest());
        self::assertNull(Lockout::strictest(null, null));
    }

    /**
     * The strictest of lockouts that end is the one that ends last, wherever
     * it is given.
     *
     * @return void
     */
    public function testTheStrictestIsTheOneThatEndsLast(): void
    {
        $early = Lockout::endingAt(AttemptScope::FACTOR, CarbonImmutable::parse('2026-11-01 12:05:00'));
        $late  = Lockout::endingAt(AttemptScope::IDENTITY, CarbonImmutable::parse('2026-11-01 12:15:00'));
        $same  = Lockout::endingAt(AttemptScope::IP, CarbonImmutable::parse('2026-11-01 12:15:00'));

        self::assertSame($late, Lockout::strictest($early, null, $late));
        self::assertSame($late, Lockout::strictest($late, $early));
        self::assertSame($late, Lockout::strictest($late, $same));
        self::assertSame($early, Lockout::strictest(null, $early));
    }

    /**
     * A disabled factor is stricter than any lockout that ends.
     *
     * @return void
     */
    public function testADisabledFactorIsTheStrictest(): void
    {
        $disabled = Lockout::disabled();
        $late     = Lockout::endingAt(AttemptScope::IDENTITY, CarbonImmutable::parse('2099-01-01 00:00:00'));

        self::assertSame($disabled, Lockout::strictest($late, $disabled));
        self::assertSame($disabled, Lockout::strictest($disabled, $late));
    }
}
