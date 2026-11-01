<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Exceptions;

/**
 * Thrown when a configured model does not live on the storage connection, so a
 * change that writes it with the package's other tables could not commit as one
 * transaction. Raised when the package boots and again before such a change: a
 * deployment fault to fix in configuration, not one to recover from at runtime.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class ModelOffStorageConnectionException extends \LogicException {}
