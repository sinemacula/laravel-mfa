<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Exceptions;

/**
 * Sign-in changed exception.
 *
 * Thrown under the identity's factor state lock when the caller or the sign-in
 * a verification captured is no longer the request's, and caught at the entry
 * point: the request answers `not_found`, counting and reporting nothing.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class SignInChangedException extends \RuntimeException {}
