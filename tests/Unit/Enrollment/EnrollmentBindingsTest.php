<?php

declare(strict_types = 1);

namespace Tests\Unit\Enrollment;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Enrollment\EnrollmentBindings;
use SineMacula\Laravel\Mfa\Enrollment\EnrollmentService;
use Tests\TestCase;

/**
 * Tests for `EnrollmentBindings`: the enrolment service is built afresh.
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
     * The enrolment service is built on every resolution.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testBuildsTheServiceOnEveryResolution(): void
    {
        self::assertFalse($this->container()->isShared(EnrollmentService::class));
        self::assertTrue($this->container()->bound(EnrollmentService::class));
        self::assertNotSame($this->container()->make(EnrollmentService::class), $this->container()->make(EnrollmentService::class));
    }
}
