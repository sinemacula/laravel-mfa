<?php

declare(strict_types = 1);

namespace Tests\Unit\Enrollment;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Enrollment\EnrollmentBindings;
use SineMacula\Laravel\Mfa\Enrollment\EnrollmentService;
use Tests\TestCase;

/**
 * Tests for `EnrollmentBindings`: the enrolment service is shared.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(EnrollmentBindings::class)]
final class EnrollmentBindingsTest extends TestCase
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
        self::assertTrue($this->container()->isShared(EnrollmentService::class));
        self::assertSame($this->container()->make(EnrollmentService::class), $this->container()->make(EnrollmentService::class));
    }
}
