<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Events;

/**
 * Dispatched when an enrolment is abandoned before it was confirmed: restarted,
 * cancelled, or out of confirmation attempts. Its pending factor is gone.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class EnrollmentAbandoned extends EnrollmentEvent {}
