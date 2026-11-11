<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Exceptions;

/**
 * Thrown when a configured model is off the storage connection, so its writes
 * could not commit in one transaction with the package's tables.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class ModelOffStorageConnectionException extends \LogicException {}
