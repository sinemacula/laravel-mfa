<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Exceptions;

/**
 * Thrown just before a commit on the storage connection, as a database that
 * refuses the commit would fail it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class CommitFailedException extends \RuntimeException {}
