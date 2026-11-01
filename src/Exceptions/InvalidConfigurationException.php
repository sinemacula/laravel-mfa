<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Exceptions;

/**
 * Thrown when the package's configuration, or a binding it needs, is wrong:
 * when the application boots and when the `mfa` manager is resolved, so a
 * misconfiguration fails before a person's first verification rather than at
 * it. The message lists every problem found, one per line, as `mfa:check`
 * prints them.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class InvalidConfigurationException extends \LogicException
{
    /**
     * Constructor.
     *
     * @param  non-empty-list<string>  $problems
     */
    public function __construct(

        /** Every problem found, each as `[<subject>] <message>`. */
        public readonly array $problems,
    ) {
        parent::__construct("The MFA configuration is invalid:\n" . implode("\n", $problems));
    }
}
