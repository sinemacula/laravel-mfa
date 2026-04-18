<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Exceptions;

/**
 * Unsupported identifier exception.
 *
 * Thrown by verification stores when the authenticatable's auth identifier
 * cannot be used as a storage key — typically when the identifier is a
 * non-scalar value such as an object or array. Fails loud rather than silently
 * collapsing distinct identities to a shared bucket.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 */
final class UnsupportedIdentifierException extends \RuntimeException {}
