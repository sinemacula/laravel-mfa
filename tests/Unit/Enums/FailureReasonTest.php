<?php

declare(strict_types = 1);

namespace Tests\Unit\Enums;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Enums\FailureReason;

/**
 * Unit tests for the `FailureReason` enum: the values listeners and
 * applications count and word, pinned so a rename fails.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FailureReason::class)]
final class FailureReasonTest extends TestCase
{
    /**
     * The failure reasons, in order, each case name with its stable value.
     *
     * @return void
     */
    public function testFailureReasonsAreTheReportedValues(): void
    {
        self::assertSame([
            'INVALID_CODE'                      => 'invalid_code',
            'EXPIRED'                           => 'expired',
            'REPLAYED'                          => 'replayed',
            'LOCKED'                            => 'locked',
            'NOT_CONFIRMED'                     => 'not_confirmed',
            'NOT_ACCEPTED'                      => 'not_accepted',
            'TYPE_NOT_ENABLED'                  => 'type_not_enabled',
            'NO_FACTOR'                         => 'no_factor',
            'NOT_FOUND'                         => 'not_found',
            'SENDING_CAPPED'                    => 'sending_capped',
            'MFA_ENROLLMENT_REQUIRED'           => 'mfa_enrollment_required',
            'IDENTITY_INACTIVE'                 => 'identity_inactive',
            'MACHINE_IDENTITY'                  => 'machine_identity',
            'NOT_FRESH'                         => 'not_fresh',
            'LAST_FACTOR'                       => 'last_factor',
            'LIMIT_REACHED'                     => 'limit_reached',
            'CREDENTIAL_ASSOCIATED'             => 'credential_associated',
            'INVALID_DESTINATION'               => 'invalid_destination',
            'SELF_SERVICE_RECOVERY_UNAVAILABLE' => 'self_service_recovery_unavailable',
        ], array_column(FailureReason::cases(), 'value', 'name'));
    }
}
