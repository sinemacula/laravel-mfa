<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Exceptions;

/**
 * Invalid factor model exception.
 *
 * Thrown by `MfaManager::factorModel()` when `config('mfa.factor.model')` is
 * missing, is not a class string, or names a class that does not implement the
 * package's `EloquentFactor` contract. Fails loud at boot/first-call rather
 * than silently falling back to the shipped default — a misconfigured factor
 * model is a deployment-time bug, not a runtime one to swallow.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 */
final class InvalidFactorModelException extends \RuntimeException {}
