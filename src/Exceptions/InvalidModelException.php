<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Exceptions;

/**
 * Thrown for a configured model class that is unusable, and for a stored time
 * or status that does not parse, which must never read as unlocked or enabled.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class InvalidModelException extends \RuntimeException {}
