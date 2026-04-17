<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Exceptions;

/**
 * Raised by test-fixture stubs when a method that the test never exercises is
 * invoked unexpectedly.
 *
 * Allows fixtures to satisfy a contract surface without committing to a real
 * implementation — the throw documents which methods are intentionally out of
 * scope and surfaces a loud failure when an unrelated test starts touching
 * them.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 *
 * @internal
 */
final class UnsupportedFixtureMethodException extends \LogicException {}
