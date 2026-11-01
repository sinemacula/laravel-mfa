<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Events;

/**
 * Dispatched when a pending factor is confirmed, and so becomes usable.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class FactorConfirmed extends EnrollmentEvent {}
