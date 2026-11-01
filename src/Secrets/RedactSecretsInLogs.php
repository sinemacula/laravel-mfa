<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Secrets;

use Illuminate\Log\Logger;
use Monolog\Logger as Monolog;

/**
 * A log channel tap that makes the `RedactSecrets` processor the last one the
 * channel's Monolog logger runs, so it sees everything the other processors
 * add, those listed in the channel's `processors` included. Monolog runs the
 * processor pushed last first, so the tap takes every processor off, pushes one
 * `RedactSecrets`, and pushes the others back in their order. A channel that
 * has the processor already, such as a stack built from tapped channels, keeps
 * one, moved to the end. A channel whose logger is not a Monolog logger is left
 * as it is.
 *
 * The package adds it to the `tap` list of every channel in `logging.channels`
 * when it boots, and applies it to every channel resolved before then, unless
 * `mfa.secrets.redact` is off; list it in a channel's `tap` yourself to cover a
 * channel configured later.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class RedactSecretsInLogs
{
    /**
     * Make the processor the last one the channel's logger runs.
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

        $processors = $monolog->getProcessors();

        while ($monolog->getProcessors() !== []) {
            $monolog->popProcessor();
        }

        $others = array_filter($processors, static fn (callable $processor): bool => !$processor instanceof RedactSecrets);

        $monolog->pushProcessor(new RedactSecrets);

        foreach (array_reverse($others) as $processor) {
            $monolog->pushProcessor($processor);
        }
    }
}
