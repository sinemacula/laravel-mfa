<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Exceptions;

/**
 * Raised by fixture identity models when `authFactors()` returns an unexpected
 * builder.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class UnexpectedBuilderTypeException extends \LogicException {}
