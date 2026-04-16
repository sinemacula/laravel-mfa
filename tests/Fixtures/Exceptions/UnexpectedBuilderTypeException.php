<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Exceptions;

/**
 * Raised by test-fixture identity models when their `authFactors()`
 * relationship returns an unexpected builder shape.
 *
 * Lives in `tests/Fixtures` because the failure is a test-only
 * scaffolding concern — production code never sees it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 *
 * @internal
 */
final class UnexpectedBuilderTypeException extends \LogicException {}
