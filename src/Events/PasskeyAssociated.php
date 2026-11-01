<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Events;

/**
 * Dispatched when a passkey is associated with the identity as a factor.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class PasskeyAssociated extends EnrollmentEvent {}
