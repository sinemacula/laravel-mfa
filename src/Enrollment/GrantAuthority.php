<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Enrollment;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Mfa\Enums\EnrollmentAuthorization;

/**
 * What authorised an enrolment to start; a grant never outlives its deadline.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class GrantAuthority
{
    /**
     * @param  \SineMacula\Laravel\Mfa\Enums\EnrollmentAuthorization  $kind
     * @param  \Carbon\CarbonImmutable  $deadline
     */
    public function __construct(

        /** Kind of authorisation. */
        public EnrollmentAuthorization $kind,

        /** When the authority ends. */
        public CarbonImmutable $deadline,
    ) {}
}
