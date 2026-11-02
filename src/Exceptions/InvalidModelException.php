<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Exceptions;

/**
 * Invalid model exception.
 *
 * Thrown when a configured model (`mfa.factor.model`,
 * `mfa.recovery_codes.model`) is not a class string, names a class that does
 * not exist, or names one that does not extend Eloquent's model and implement
 * the package's contract for it. It fails loudly at boot or at first use rather
 * than falling back to the shipped model: a misconfigured model is a deployment
 * bug, not one to swallow at runtime. Also thrown when a factor's lockout
 * deadline or disabled time does not read as a time, which must not read as
 * unlocked or enabled.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class InvalidModelException extends \RuntimeException {}
