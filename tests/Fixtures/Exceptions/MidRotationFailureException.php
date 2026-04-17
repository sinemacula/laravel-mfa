<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Exceptions;

/**
 * Raised by an event listener wired inside the backup-code rotation test to
 * simulate a mid-rotation failure. Lets the test prove the outer transaction
 * rolls back every write on the factor model's own connection.
 *
 * Test-only scaffold — production code never sees it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 *
 * @internal
 */
final class MidRotationFailureException extends \RuntimeException {}
