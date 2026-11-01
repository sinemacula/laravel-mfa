<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Secrets;

use Illuminate\Log\Logger;
use Monolog\Logger as Monolog;

/**
 * A log channel tap that pushes the `RedactSecrets` processor onto the
 * channel's Monolog logger, once, so a channel that already has it, such as a
 * stack built from tapped channels, is not given it again. A channel whose
 * logger is not a Monolog logger is left as it is.
 *
 * The package adds it to the `tap` list of every channel in
 * `logging.channels` when it boots, unless `mfa.secrets.redact` is off; list it
 * in a channel's `tap` yourself to cover a channel configured later.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class RedactSecretsInLogs
{
    /**
     * Push the processor onto the channel's logger.
     *
     * @param  \Illuminate\Log\Logger  $logger
     * @return void
     */
    public function __invoke(Logger $logger): void
    {
        $monolog = $logger->getLogger();

        if (!$monolog instanceof Monolog) {
            return;
        }

        foreach ($monolog->getProcessors() as $processor) {
            if ($processor instanceof RedactSecrets) {
                return;
            }
        }

        $monolog->pushProcessor(new RedactSecrets);
    }
}
