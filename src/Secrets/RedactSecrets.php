<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Secrets;

use Monolog\LogRecord;
use Monolog\Processor\ProcessorInterface;

/**
 * A Monolog processor that redacts the secrets, codes and full destinations in
 * a log record before any handler writes it: provisioning URIs in the message,
 * and everything `Redactor` redacts in the context and the extra data, which
 * includes scrubbing the trace of a logged exception.
 *
 * The package pushes it onto every configured log channel through
 * `RedactSecretsInLogs`, unless `mfa.secrets.redact` is off. It can also be
 * listed in a `monolog` channel's `processors`.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class RedactSecrets implements ProcessorInterface
{
    /**
     * The record with its secrets redacted.
     *
     * @param  \Monolog\LogRecord  $record
     * @return \Monolog\LogRecord
     */
    #[\Override]
    public function __invoke(LogRecord $record): LogRecord
    {
        return $record->with(
            message: Redactor::redactString($record->message),
            context: Redactor::redact($record->context),
            extra: Redactor::redact($record->extra),
        );
    }
}
