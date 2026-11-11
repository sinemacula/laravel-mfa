<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Exceptions;

/**
 * Thrown when an auth identifier is not scalar, rather than letting distinct
 * identities share a storage key.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class UnsupportedIdentifierException extends \RuntimeException {}
