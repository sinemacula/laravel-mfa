<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Secrets;

use Illuminate\Log\Logger;
use Monolog\Logger as Monolog;

/**
 * Log channel tap that makes `RedactSecrets` the last processor to run, so it
 * sees what the others add. Monolog runs the last-pushed processor first, so it
 * is pushed before the rest. List it in `tap` for channels configured later.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class RedactSecretsInLogs
{
    /**
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
