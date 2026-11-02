<?php

declare(strict_types = 1);

namespace Tests\Unit\Verification;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Verification\VerificationBindings;
use SineMacula\Laravel\Mfa\Verification\VerificationService;
use Tests\TestCase;

/**
 * Tests for `VerificationBindings`: the verification service is built afresh.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(VerificationBindings::class)]
final class VerificationBindingsTest extends TestCase
{
    /**
     * The verification service is built on every resolution.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testBuildsTheServiceOnEveryResolution(): void
    {
        self::assertFalse($this->container()->isShared(VerificationService::class));
        self::assertTrue($this->container()->bound(VerificationService::class));
        self::assertNotSame($this->container()->make(VerificationService::class), $this->container()->make(VerificationService::class));
    }
}
