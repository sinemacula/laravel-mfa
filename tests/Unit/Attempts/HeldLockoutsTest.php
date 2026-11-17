<?php

declare(strict_types = 1);

namespace Tests\Unit\Attempts;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Attempts\AttemptSettings;
use SineMacula\Laravel\Mfa\Attempts\HeldLockouts;
use SineMacula\Laravel\Mfa\Enums\AttemptScope;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Models\IdentityState;
use Tests\TestCase;

/**
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(HeldLockouts::class)]
final class HeldLockoutsTest extends TestCase
{
    /** @var \Carbon\CarbonImmutable The instant lockouts are judged at. */
    private CarbonImmutable $now;

    /**
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->now = CarbonImmutable::parse('2026-11-01 12:00:00');

        config()->set('mfa.attempts.failure_ceiling', 3);
    }

    /**
     * @return void
     */
    public function testAnIdentityLockedUntilLaterIsHeld(): void
    {
        $lockout = HeldLockouts::identity($this->state(lockedUntil: $this->now->addSecond()), $this->now);

        self::assertSame(AttemptScope::IDENTITY, $lockout?->scope);
        self::assertSame($this->now->addSecond()->getTimestamp(), $lockout->until?->getTimestamp());
    }

    /**
     * Nor one with no state or no lock.
     *
     * @return void
     */
    public function testAnIdentityLockThatHasEndedIsNotHeld(): void
    {
        self::assertNull(HeldLockouts::identity($this->state(lockedUntil: $this->now), $this->now));
        self::assertNull(HeldLockouts::identity($this->state(), $this->now));
        self::assertNull(HeldLockouts::identity(null, $this->now));
    }

    /**
     * @return void
     */
    public function testAnIdentityAtTheFailureCeilingIsDisabled(): void
    {
        $lockout = HeldLockouts::identityCeiling($this->state(failures: 3), $this->settings());

        self::assertSame(AttemptScope::IDENTITY, $lockout?->scope);
        self::assertTrue($lockout->isDisabled());
    }

    /**
     * @return void
     */
    public function testAnIdentityBelowTheFailureCeilingIsNotDisabled(): void
    {
        self::assertNull(HeldLockouts::identityCeiling($this->state(failures: 2), $this->settings()));
        self::assertNull(HeldLockouts::identityCeiling(null, $this->settings()));
    }

    /**
     * Whatever its lock says.
     *
     * @return void
     */
    public function testADisabledFactorIsDisabled(): void
    {
        $lockout = HeldLockouts::factor($this->factor(disabledAt: $this->now, lockedUntil: $this->now->addHour()), $this->now);

        self::assertSame(AttemptScope::FACTOR, $lockout?->scope);
        self::assertTrue($lockout->isDisabled());
    }

    /**
     * @return void
     */
    public function testAFactorLockedUntilLaterIsHeld(): void
    {
        $lockout = HeldLockouts::factor($this->factor(lockedUntil: $this->now->addSecond()), $this->now);

        self::assertSame(AttemptScope::FACTOR, $lockout?->scope);
        self::assertSame($this->now->addSecond()->getTimestamp(), $lockout->until?->getTimestamp());
    }

    /**
     * Nor one with no lock, nor no factor.
     *
     * @return void
     */
    public function testAFactorLockThatHasEndedIsNotHeld(): void
    {
        self::assertNull(HeldLockouts::factor($this->factor(lockedUntil: $this->now), $this->now));
        self::assertNull(HeldLockouts::factor($this->factor(), $this->now));
        self::assertNull(HeldLockouts::factor(null, $this->now));
    }

    /**
     * @return void
     */
    public function testTheIdentityCeilingHoldsAnAttemptWithNoFactor(): void
    {
        $lockout = HeldLockouts::strictest($this->state(failures: 3, lockedUntil: $this->now->addHour()), null, $this->settings(), $this->now);

        self::assertSame(AttemptScope::IDENTITY, $lockout?->scope);
        self::assertTrue($lockout->isDisabled());
    }

    /**
     * Only the timed locks of the identity and the factor apply.
     *
     * @return void
     */
    public function testTheIdentityCeilingDoesNotHoldAnAttemptWithAFactor(): void
    {
        $state   = $this->state(failures: 3, lockedUntil: $this->now->addMinute());
        $lockout = HeldLockouts::strictest($state, $this->factor(lockedUntil: $this->now->addHour()), $this->settings(), $this->now);

        self::assertSame(AttemptScope::FACTOR, $lockout?->scope);
        self::assertSame($this->now->addHour()->getTimestamp(), $lockout->until?->getTimestamp());
        self::assertNull(HeldLockouts::strictest($this->state(failures: 3), $this->factor(), $this->settings(), $this->now));
    }

    /**
     * @param  int  $failures
     * @param  ?\Carbon\CarbonImmutable  $lockedUntil
     * @return \SineMacula\Laravel\Mfa\Models\IdentityState
     */
    private function state(int $failures = 0, ?CarbonImmutable $lockedUntil = null): IdentityState
    {
        return new IdentityState(['consecutive_failures' => $failures, 'locked_until' => $lockedUntil]);
    }

    /**
     * @param  ?\Carbon\CarbonImmutable  $disabledAt
     * @param  ?\Carbon\CarbonImmutable  $lockedUntil
     * @return \SineMacula\Laravel\Mfa\Models\Factor
     */
    private function factor(?CarbonImmutable $disabledAt = null, ?CarbonImmutable $lockedUntil = null): Factor
    {
        return (new Factor)->forceFill(['disabled_at' => $disabledAt, 'locked_until' => $lockedUntil]);
    }

    /**
     * @return \SineMacula\Laravel\Mfa\Attempts\AttemptSettings
     */
    private function settings(): AttemptSettings
    {
        return new AttemptSettings(config());
    }
}
