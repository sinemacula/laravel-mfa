<?php

declare(strict_types = 1);

namespace Tests\Unit\Seams;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Contracts\Reauthenticator;
use SineMacula\Laravel\Mfa\Seams\RefusingReauthenticator;
use SineMacula\Laravel\Mfa\Seams\SeamBindings;
use Tests\TestCase;

/**
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SeamBindings::class)]
final class SeamBindingsTest extends TestCase
{
    /**
     * Built afresh, and the application's own binding replaces it.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testBindsTheRefusingReauthenticatorByDefault(): void
    {
        self::assertInstanceOf(RefusingReauthenticator::class, $this->container()->make(Reauthenticator::class));
        self::assertFalse($this->container()->isShared(Reauthenticator::class));

        $own = \Mockery::mock(Reauthenticator::class);

        $this->container()->instance(Reauthenticator::class, $own);

        self::assertSame($own, $this->container()->make(Reauthenticator::class));
    }
}
