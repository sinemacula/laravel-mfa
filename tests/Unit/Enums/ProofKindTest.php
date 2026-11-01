<?php

declare(strict_types = 1);

namespace Tests\Unit\Enums;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Enums\ProofKind;
use SineMacula\Laravel\Mfa\Enums\Purpose;

/**
 * Unit tests for the `ProofKind` enum: its stable values, and the purpose a
 * kind of proof must carry.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ProofKind::class)]
final class ProofKindTest extends TestCase
{
    /**
     * The proof kinds, in order, with their stable values.
     *
     * @return void
     */
    public function testProofKindsAreTheStableValues(): void
    {
        self::assertSame([
            'first_factor',
            'first_factor_reauthentication',
            'additional_factor',
            'recovery_code',
        ], array_map(static fn (ProofKind $kind): string => $kind->value, ProofKind::cases()));
    }

    /**
     * A first factor is proved at sign-in and a reauthentication with it
     * carries the reauthenticate purpose; the others may serve any purpose.
     *
     * @return void
     */
    public function testThePurposeEachKindRequires(): void
    {
        self::assertSame(Purpose::SIGN_IN, ProofKind::FIRST_FACTOR->requiredPurpose());
        self::assertSame(Purpose::REAUTHENTICATE, ProofKind::FIRST_FACTOR_REAUTHENTICATION->requiredPurpose());
        self::assertNull(ProofKind::ADDITIONAL_FACTOR->requiredPurpose());
        self::assertNull(ProofKind::RECOVERY_CODE->requiredPurpose());
    }

    /**
     * Only a recovery code is proved without a channel.
     *
     * @return void
     */
    public function testOnlyARecoveryCodeHasNoChannel(): void
    {
        $kinds = array_values(array_filter(ProofKind::cases(), static fn (ProofKind $kind): bool => $kind->hasChannel()));

        self::assertSame([
            ProofKind::FIRST_FACTOR,
            ProofKind::FIRST_FACTOR_REAUTHENTICATION,
            ProofKind::ADDITIONAL_FACTOR,
        ], $kinds);
    }
}
