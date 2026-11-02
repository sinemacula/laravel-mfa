<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Exceptions;

/**
 * Thrown just before a commit on the storage connection, as a database that
 * loses the connection or refuses the commit would fail it.
 *
 * Test-only scaffold — production code never sees it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class CommitFailedException extends \RuntimeException {}
