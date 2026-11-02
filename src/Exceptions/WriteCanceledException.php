<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Exceptions;

/**
 * Write cancelled exception.
 *
 * Thrown when a model event (a `saving`, `creating` or `deleting` listener or
 * observer returning `false`) cancels a save or a deletion the package needs
 * made. A change that cannot be made whole must never be reported as made, so
 * the change it is part of rolls back instead of committing without it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class WriteCanceledException extends \RuntimeException {}
