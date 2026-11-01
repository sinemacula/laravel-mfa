<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Events;

/**
 * Dispatched when an enrolment starts: a pending factor now awaits confirmation
 * by a first valid code or assertion.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class EnrollmentStarted extends EnrollmentEvent {}
