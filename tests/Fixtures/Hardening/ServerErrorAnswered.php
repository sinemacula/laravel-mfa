<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Hardening;

/**
 * A server error the HTTP kernel rendered, so a flow through the kernel fails
 * the way a direct call does.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ServerErrorAnswered extends \RuntimeException {}
