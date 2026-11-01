<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Exceptions;

/**
 * Table already exists exception.
 *
 * Thrown by a shipped migration when the table name it is configured with
 * collides with an existing table. Carries a message naming the setting to
 * change to avoid the collision.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class TableAlreadyExistsException extends \RuntimeException {}
