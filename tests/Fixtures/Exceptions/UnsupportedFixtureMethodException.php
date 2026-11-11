<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Exceptions;

/**
 * Raised by a fixture method that satisfies a contract but is out of scope for
 * its tests.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class UnsupportedFixtureMethodException extends \LogicException {}
