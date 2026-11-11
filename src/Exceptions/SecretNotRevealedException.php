<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Exceptions;

/**
 * Thrown when a `Secrets\RevealedSecret` is cast, encoded or serialised: its
 * plaintext leaves only through `reveal()` or `Secrets\SecretResponse`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class SecretNotRevealedException extends \LogicException {}
