<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Enrollment;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Mfa\Enums\EnrollmentAuthorization;

/**
 * What authorised an enrolment to start and the instant that authority ends,
 * which an enrolment grant lives no longer than.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class GrantAuthority
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Mfa\Enums\EnrollmentAuthorization  $kind
     * @param  \Carbon\CarbonImmutable  $deadline
     */
    public function __construct(

        /** What authorised the enrolment. */
        public EnrollmentAuthorization $kind,

        /** The instant the authority ends. */
        public CarbonImmutable $deadline,
    ) {}
}
