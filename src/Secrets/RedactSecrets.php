<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Secrets;

use Monolog\LogRecord;
use Monolog\Processor\ProcessorInterface;

/**
 * A Monolog processor that redacts the secrets, codes and full destinations in
 * a log record before any handler writes it: everything `Redactor` redacts in
 * the context and the extra data, which includes scrubbing the message and the
 * trace of a logged exception, and, in the record's message, provisioning URIs
 * and every sensitive value the context and the extra data hold.
 *
 * The context and the extra data are normalised first, each object turned into
 * what Monolog would log for it (see `Redactor::normalize()`), and the values
 * are collected from that same form before anything is redacted (see
 * `SensitiveValues`): a value marked as sensitive, a value under a key naming a
 * secret, a code or a destination, in an object's form too, a code message's
 * code and recipients, and what a logged exception recorded in its trace.
 *
 * They leave the record's message, so a message copied from an exception's
 * before the exception was scrubbed loses them too, as one logged with
 * `Log::error($e->getMessage(), ['exception' => $e])` does. Every logged
 * exception's chain is scrubbed of them as well, so the values the record holds
 * leave its exceptions' messages even when PHP recorded no arguments.
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
        $context = Redactor::normalize($record->context);
        $extra   = Redactor::normalize($record->extra);
        $values  = SensitiveValues::inLogValues($context)->with(SensitiveValues::inLogValues($extra));

        return $record->with(
            message: Redactor::redactMessage($record->message, $values),
            context: Redactor::redactNormalized($context, $values),
            extra: Redactor::redactNormalized($extra, $values),
        );
    }
}
