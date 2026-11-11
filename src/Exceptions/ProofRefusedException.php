<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Exceptions;

/**
 * Thrown by a proof store asked to record a proof not bound to the identity's
 * current sign-in, so the surrounding change rolls back.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class ProofRefusedException extends \RuntimeException {}
