<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Secrets;

use Monolog\LogRecord;
use Monolog\Processor\ProcessorInterface;

/**
 * A channel's own processor that adds a submitted code to every record's extra
 * data, as one that copies request input would.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class AddsCodeToExtra implements ProcessorInterface
{
    /** @var string The code added. */
    public const string CODE = '739104';

    /**
     * The record with the code in its extra data.
     *
     * @param  \Monolog\LogRecord  $record
     * @return \Monolog\LogRecord
     */
    #[\Override]
    public function __invoke(LogRecord $record): LogRecord
    {
        return $record->with(extra: [...$record->extra, 'code' => self::CODE]);
    }
}
