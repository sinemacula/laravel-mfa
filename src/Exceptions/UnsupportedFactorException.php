<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Exceptions;

/**
 * Thrown when a factor lacks a capability, such as delivered codes needing a
 * stored model.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class UnsupportedFactorException extends \RuntimeException {}
