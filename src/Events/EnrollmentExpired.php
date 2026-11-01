<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Events;

/**
 * Dispatched when an enrolment's grant expires before it was confirmed. Its
 * pending factor is gone.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class EnrollmentExpired extends EnrollmentEvent {}
