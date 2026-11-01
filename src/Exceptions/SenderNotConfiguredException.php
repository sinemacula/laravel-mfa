<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Exceptions;

/**
 * Sender not configured exception.
 *
 * Thrown by the default SMS and email senders, which the package binds until
 * the application binds its own: a code is never dropped silently because
 * nothing was bound to deliver it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class SenderNotConfiguredException extends \RuntimeException
{
    /**
     * Build the exception naming the contract the application must bind.
     *
     * @param  class-string  $contract
     * @return self
     */
    public static function for(string $contract): self
    {
        return new self(sprintf('No sender is bound to deliver codes: bind an implementation of %s in a service provider.', $contract));
    }
}
