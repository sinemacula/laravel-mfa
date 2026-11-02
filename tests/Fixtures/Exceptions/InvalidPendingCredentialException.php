<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Exceptions;

/**
 * Thrown by a pending session resolver fixture for a pending credential that
 * does not validate, as an authentication layer would refuse it.
 *
 * Test-only scaffold — production code never sees it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class InvalidPendingCredentialException extends \RuntimeException {}
