<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Exceptions;

/**
 * Proof refused exception.
 *
 * Thrown by a proof store asked to record a proof it cannot keep: one that is
 * not bound to its identity's current sign-in. A proof that cannot be recorded
 * must never be reported as recorded, so the change the call is part of rolls
 * back.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class ProofRefusedException extends \RuntimeException {}
