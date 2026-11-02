<?php

declare(strict_types = 1);

namespace Tests\Unit\Requirements;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Proofs\VerificationGeneration;
use SineMacula\Laravel\Mfa\Requirements\ReenrollmentObligation;
use Tests\Fixtures\Identities\NonEloquentIdentity;
use Tests\TestCase;

/**
 * Tests for `ReenrollmentObligation`: an identity with no row has no
 * obligation, and what is recorded is what is read back, whichever way it goes.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ReenrollmentObligation::class)]
final class ReenrollmentObligationTest extends TestCase
{
    /**
     * An obligation is recorded as stated, a later `false` clears an earlier
     * `true`, and ending it clears it too.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRecordsAndEndsTheObligation(): void
    {
        $identity = new NonEloquentIdentity('plain-1');

        self::assertFalse(ReenrollmentObligation::isRequired($identity));

        VerificationGeneration::advance($identity);

        ReenrollmentObligation::record($identity, true);

        self::assertTrue(ReenrollmentObligation::isRequired($identity));

        ReenrollmentObligation::record($identity, false);

        self::assertFalse(ReenrollmentObligation::isRequired($identity));

        ReenrollmentObligation::record($identity, true);
        ReenrollmentObligation::end($identity);

        self::assertFalse(ReenrollmentObligation::isRequired($identity));
    }
}
