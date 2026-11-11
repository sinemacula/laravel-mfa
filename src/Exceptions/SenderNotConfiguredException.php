<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Exceptions;

/**
 * Thrown by the default SMS and email senders, so a code is never dropped
 * silently when the application has bound none.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class SenderNotConfiguredException extends \RuntimeException
{
    /**
     * @param  class-string  $contract
     * @return self
     */
    public static function for(string $contract): self
    {
        return new self(sprintf('No sender is bound to deliver codes: bind an implementation of %s in a service provider.', $contract));
    }
}
