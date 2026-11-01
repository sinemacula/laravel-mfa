<?php

declare(strict_types = 1);

namespace Tests\Unit\Enrolment;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Enrolment\EnrolmentBindings;
use SineMacula\Laravel\Mfa\Enrolment\EnrolmentService;
use Tests\TestCase;

/**
 * Tests for `EnrolmentBindings`: the enrolment service is shared.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(EnrolmentBindings::class)]
final class EnrolmentBindingsTest extends TestCase
{
    /**
     * The enrolment service is a singleton.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testRegistersTheServiceAsASingleton(): void
    {
        self::assertTrue($this->container()->isShared(EnrolmentService::class));
        self::assertSame($this->container()->make(EnrolmentService::class), $this->container()->make(EnrolmentService::class));
    }
}
