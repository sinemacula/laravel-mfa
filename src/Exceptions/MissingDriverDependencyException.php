<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Exceptions;

/**
 * Missing driver dependency exception.
 *
 * Thrown when an MFA driver requires a package that is not
 * installed. Provides a helpful message guiding the developer
 * to install the missing dependency.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 */
final class MissingDriverDependencyException extends \RuntimeException {}
