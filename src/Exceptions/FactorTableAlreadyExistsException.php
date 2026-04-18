<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Exceptions;

/**
 * Factor table already exists exception.
 *
 * Thrown by the shipped factors migration when the configured table name
 * collides with an existing table. Carries a message telling the consumer how
 * to rebind `mfa.factor.table` to avoid the collision.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 */
final class FactorTableAlreadyExistsException extends \RuntimeException {}
