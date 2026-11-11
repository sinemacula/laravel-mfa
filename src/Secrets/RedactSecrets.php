<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Secrets;

use Monolog\LogRecord;
use Monolog\Processor\ProcessorInterface;

/**
 * Monolog processor that redacts secrets, codes and full destinations from a
 * record's context, extra data and message before any handler writes it.
 *
 * Values are collected before redaction so a message copied from an exception,
 * as in `Log::error($e->getMessage(), ['exception' => $e])`, loses them too.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class RedactSecrets implements ProcessorInterface
{
    /**
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
