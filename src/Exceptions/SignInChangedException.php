<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Exceptions;

/**
 * Thrown under the factor state lock when the captured sign-in is no longer the
 * request's; the entry point answers `not_found` and counts nothing.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class SignInChangedException extends \RuntimeException {}
