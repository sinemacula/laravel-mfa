<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Exceptions;

/**
 * Secret not revealed exception.
 *
 * Thrown when a `Secrets\RevealedSecret` is cast to a string, encoded as JSON,
 * serialised or unserialised: the plaintext leaves the value only through an
 * explicit `reveal()`, or through `Secrets\SecretResponse`, which reveals it
 * into a response that is never stored. Reaching for it any other way is a bug
 * in the calling code, so it fails loudly rather than send or keep the secret.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class SecretNotRevealedException extends \LogicException {}
