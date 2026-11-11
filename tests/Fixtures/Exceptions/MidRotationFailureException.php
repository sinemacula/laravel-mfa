<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Exceptions;

/**
 * Thrown partway through a factor state change to prove the transaction rolls
 * back and releases its lock.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class MidRotationFailureException extends \RuntimeException {}
