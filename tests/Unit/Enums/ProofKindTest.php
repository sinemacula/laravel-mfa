<?php

declare(strict_types = 1);

namespace Tests\Unit\Enums;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Enums\ProofKind;
use SineMacula\Laravel\Mfa\Enums\Purpose;

/**
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ProofKind::class)]
final class ProofKindTest extends TestCase
{
    /**
     * Pinned so a rename fails.
     *
     * @return void
     */
    public function testProofKindsAreTheStableValues(): void
    {
        self::assertSame([
            'FIRST_FACTOR'                  => 'first_factor',
            'FIRST_FACTOR_REAUTHENTICATION' => 'first_factor_reauthentication',
            'ADDITIONAL_FACTOR'             => 'additional_factor',
            'RECOVERY_CODE'                 => 'recovery_code',
        ], array_column(ProofKind::cases(), 'value', 'name'));
    }

    /**
     * A first factor is proved at sign-in and reauthenticates with that
     * purpose; the others serve any.
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
