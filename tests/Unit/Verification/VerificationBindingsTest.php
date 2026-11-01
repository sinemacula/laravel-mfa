<?php

declare(strict_types = 1);

namespace Tests\Unit\Verification;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Verification\VerificationBindings;
use SineMacula\Laravel\Mfa\Verification\VerificationService;
use Tests\TestCase;

/**
 * Tests for `VerificationBindings`: the verification service is shared.
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
     * The verification service is a singleton.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testRegistersTheServiceAsASingleton(): void
    {
        self::assertTrue($this->container()->isShared(VerificationService::class));
        self::assertSame($this->container()->make(VerificationService::class), $this->container()->make(VerificationService::class));
    }
}
