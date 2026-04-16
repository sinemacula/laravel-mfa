<?php

declare(strict_types = 1);

namespace Tests\Unit\Policies;

use Illuminate\Contracts\Auth\Authenticatable;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Contracts\MfaPolicy;
use SineMacula\Laravel\Mfa\Policies\NullMfaPolicy;

/**
 * Unit tests for the `NullMfaPolicy` default policy implementation.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 *
 * @internal
 */
final class NullMfaPolicyTest extends TestCase
{
    public function testShouldEnforceAlwaysReturnsFalse(): void
    {
        $policy   = new NullMfaPolicy;
        $identity = self::createStub(Authenticatable::class);

        self::assertFalse($policy->shouldEnforce($identity));
    }

    public function testImplementsMfaPolicyContract(): void
    {
        self::assertInstanceOf(MfaPolicy::class, new NullMfaPolicy);
    }
}
