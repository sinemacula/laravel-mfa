<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Exceptions;

/**
 * Unsupported factor exception.
 *
 * Thrown when a factor does not satisfy a stricter capability requirement:
 * typically a factor that is not a stored model, which delivered codes and
 * backup-code consumption need.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class UnsupportedFactorException extends \RuntimeException {}
