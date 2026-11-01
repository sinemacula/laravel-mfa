<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Events;

/**
 * Dispatched when a factor is confirmed through the bootstrap path, during a
 * pending sign-in, by an identity that had none. Anyone holding the first
 * factor can take that path, so the application can tell the person.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class BootstrapEnrollmentCompleted extends EnrollmentEvent {}
