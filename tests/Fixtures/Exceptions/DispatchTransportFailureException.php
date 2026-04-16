<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Exceptions;

/**
 * Raised by the dispatch-tracking OTP driver fixture to simulate a
 * transport-layer failure during issueChallenge().
 *
 * Lives in `tests/Fixtures` because the failure is a test scaffold
 * concern — production code never sees it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 *
 * @internal
 */
final class DispatchTransportFailureException extends \RuntimeException {}
