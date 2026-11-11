<?php

declare(strict_types = 1);

namespace Tests\Unit\Enrollment;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Enrollment\EnrollmentBindings;
use SineMacula\Laravel\Mfa\Enrollment\EnrollmentService;
use Tests\TestCase;

/**
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(EnrollmentBindings::class)]
final class EnrollmentBindingsTest extends TestCase
{
    /**
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
