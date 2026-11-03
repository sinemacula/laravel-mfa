<?php

declare(strict_types = 1);

namespace Tests\Unit\Enrollment;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Enrollment\PendingEnrollments;
use SineMacula\Laravel\Mfa\Enums\EnrollmentAuthorization;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
use Tests\Fixtures\Identities\SecondaryUser;
use Tests\Fixtures\Identities\TestUser;
use Tests\TestCase;

/**
 * An enrolment is bound to exactly the owner it was started for, through its
 * application: an identity sharing its type or its key, but not both, is not
 * that owner.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PendingEnrollments::class)]
final class PendingEnrollmentsTest extends TestCase
{
    /**
     * An enrolment is bound to its own owner's binding only: not to another
     * identity of the same type, the same key of another type, or another
     * application.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAnEnrollmentIsBoundToItsOwnerOnly(): void
    {
        $enrollments = $this->container()->make(PendingEnrollments::class);
        $binding     = self::binding(TestUser::class, '1', 'web');
        $expiresAt   = CarbonImmutable::now()->addHour();
        $enrollment  = $enrollments->create('01jfactor0000000000000000f1', hash('sha256', 'grant'), $binding, 0, EnrollmentAuthorization::STEP_UP, $expiresAt);

        self::assertTrue($enrollments->isBound($enrollment, $binding, false));
        self::assertFalse($enrollments->isBound($enrollment, self::binding(TestUser::class, '2', 'web'), false));
        self::assertFalse($enrollments->isBound($enrollment, self::binding(SecondaryUser::class, '1', 'web'), false));
        self::assertFalse($enrollments->isBound($enrollment, self::binding(TestUser::class, '1', 'admin'), false));
    }

    /**
     * An enrolment binding on the shared sign-in.
     *
     * @param  string  $type
     * @param  string  $key
     * @param  string  $application
     * @return \SineMacula\Laravel\Mfa\Proofs\ProofBinding
     */
    private static function binding(string $type, string $key, string $application): ProofBinding
    {
        return new ProofBinding($type, $key, $application, 'sign-in-1', Purpose::ENROLLMENT);
    }
}
