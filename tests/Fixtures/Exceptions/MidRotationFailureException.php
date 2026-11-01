<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Exceptions;

/**
 * Thrown from inside a factor state change to simulate a failure partway
 * through, so a test can prove the transaction rolls back every write on the
 * storage connection and releases its lock.
 *
 * Test-only scaffold — production code never sees it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class MidRotationFailureException extends \RuntimeException {}
