<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Hardening;

/**
 * Stands for a server error the HTTP kernel answered with, so a flow through
 * the kernel fails the way one that calls the package directly does. It wraps
 * whatever the kernel rendered, for a test to search.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ServerErrorAnswered extends \RuntimeException {}
