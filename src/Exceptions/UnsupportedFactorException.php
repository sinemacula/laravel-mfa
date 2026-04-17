<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Exceptions;

/**
 * Unsupported factor exception.
 *
 * Thrown by drivers when they receive a `Factor` instance that does not satisfy
 * the driver's stricter capability requirements — typically a non-persistable
 * factor handed to a driver that needs to write back (OTP code issuance,
 * backup-code consumption).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 */
final class UnsupportedFactorException extends \RuntimeException {}
