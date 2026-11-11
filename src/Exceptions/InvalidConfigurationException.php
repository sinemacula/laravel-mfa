<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Exceptions;

/**
 * Thrown at boot and when the `mfa` manager resolves, so a misconfiguration
 * fails before anyone's first verification.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class InvalidConfigurationException extends \LogicException
{
    /**
     * @param  non-empty-list<string>  $problems
     */
    public function __construct(

        /** Every problem found, each as `[<subject>] <message>`. */
        public readonly array $problems,
    ) {
        parent::__construct("The MFA configuration is invalid:\n" . implode("\n", $problems));
    }
}
