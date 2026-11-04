<?php

declare(strict_types = 1);

namespace Tests\Unit\Requirements;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Enums\FactorChangeMade;
use SineMacula\Laravel\Mfa\Enums\FactorStatus;
use SineMacula\Laravel\Mfa\Factors\FactorSummary;
use SineMacula\Laravel\Mfa\Requirements\Requirement;
use SineMacula\Laravel\Mfa\Requirements\SessionChange;
use Tests\Fixtures\Identities\NonEloquentIdentity;

/**
 * Unit tests for `SessionChange`: it carries the change as made, and is made
 * only on a sign-in with a session id.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SessionChange::class)]
final class SessionChangeTest extends TestCase
{
    /**
     * The change carries what it is given.
     *
     * @return void
     */
    public function testCarriesTheChange(): void
    {
        $identity    = new NonEloquentIdentity;
        $factor      = self::factor();
        $outstanding = Requirement::none()->withAdditionalVerification();

        $change = new SessionChange($identity, 'web', 'session-1', FactorChangeMade::PASSKEY_REGISTERED, $factor, $outstanding);

        self::assertSame($identity, $change->identity);
        self::assertSame('web', $change->application);
        self::assertSame('session-1', $change->session);
        self::assertSame(FactorChangeMade::PASSKEY_REGISTERED, $change->change);
        self::assertSame($factor, $change->factor);
        self::assertSame($outstanding, $change->outstanding);
        self::assertNull((new SessionChange($identity, 'web', 'session-1', FactorChangeMade::CONFIRMED, $factor, null))->outstanding);
    }

    /**
     * A blank session id is refused.
     *
     * @return void
     */
    public function testRefusesABlankSession(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('A factor change is made on a sign-in, so its session id must not be blank.');

        new SessionChange(new NonEloquentIdentity, 'web', ' ', FactorChangeMade::REMOVED, self::factor(), null);
    }

    /**
     * A confirmed TOTP factor.
     *
     * @return \SineMacula\Laravel\Mfa\Factors\FactorSummary
     */
    private static function factor(): FactorSummary
    {
        return new FactorSummary('factor-totp', 'totp', null, null, FactorStatus::CONFIRMED, false, null);
    }
}
