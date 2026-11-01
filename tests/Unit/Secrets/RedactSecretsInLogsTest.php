<?php

declare(strict_types = 1);

namespace Tests\Unit\Secrets;

use Illuminate\Log\Logger;
use Monolog\Handler\TestHandler;
use Monolog\Logger as Monolog;
use Monolog\LogRecord;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use SineMacula\Laravel\Mfa\Secrets\RedactSecrets;
use SineMacula\Laravel\Mfa\Secrets\RedactSecretsInLogs;
use Tests\Fixtures\Secrets\AddsCodeToExtra;

/**
 * Tests for the `RedactSecretsInLogs` tap: one processor runs last on a Monolog
 * logger, after every other processor, and any other logger is left as it is.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RedactSecretsInLogs::class)]
final class RedactSecretsInLogsTest extends TestCase
{
    /**
     * The processor is pushed onto the channel's Monolog logger.
     *
     * @return void
     */
    public function testPushesTheProcessor(): void
    {
        $monolog = new Monolog('mfa');

        (new RedactSecretsInLogs)(new Logger($monolog));

        self::assertCount(1, $monolog->getProcessors());
        self::assertInstanceOf(RedactSecrets::class, $monolog->getProcessors()[0]);
    }

    /**
     * The processor runs after every processor the logger has, which keep their
     * order.
     *
     * @return void
     */
    public function testRunsTheProcessorLast(): void
    {
        $first   = static fn (LogRecord $record): LogRecord => $record;
        $second  = static fn (LogRecord $record): LogRecord => $record;
        $monolog = new Monolog('mfa', [], [$first, $second]);

        (new RedactSecretsInLogs)(new Logger($monolog));

        $processors = $monolog->getProcessors();

        self::assertCount(3, $processors);
        self::assertSame([$first, $second], array_slice($processors, 0, 2));
        self::assertInstanceOf(RedactSecrets::class, $processors[2]);
    }

    /**
     * What a processor adds to a record is redacted, since the redaction runs
     * after it.
     *
     * @return void
     */
    public function testRedactsWhatOtherProcessorsAdd(): void
    {
        $handler = new TestHandler;
        $monolog = new Monolog('mfa', [$handler], [new AddsCodeToExtra]);

        (new RedactSecretsInLogs)(new Logger($monolog));

        $monolog->info('Code checked.');

        self::assertSame('[redacted]', $handler->getRecords()[0]->extra['code'] ?? null);
    }

    /**
     * A logger that has the processor already keeps one, moved to run last,
     * however many it had and however often it is tapped.
     *
     * @return void
     */
    public function testKeepsOneProcessorRunningLast(): void
    {
        $other   = static fn (LogRecord $record): LogRecord => $record;
        $monolog = new Monolog('mfa', [], [new RedactSecrets, $other, new RedactSecrets]);

        (new RedactSecretsInLogs)(new Logger($monolog));
        (new RedactSecretsInLogs)(new Logger($monolog));

        $processors = $monolog->getProcessors();

        self::assertCount(2, $processors);
        self::assertSame($other, $processors[0]);
        self::assertInstanceOf(RedactSecrets::class, $processors[1]);
    }

    /**
     * A logger other than Monolog's is left as it is.
     *
     * @return void
     */
    public function testLeavesOtherLoggersAlone(): void
    {
        $logger = new Logger(new NullLogger);

        (new RedactSecretsInLogs)($logger);

        self::assertInstanceOf(NullLogger::class, $logger->getLogger());
    }
}
