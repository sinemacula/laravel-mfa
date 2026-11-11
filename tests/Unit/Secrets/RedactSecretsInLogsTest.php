<?php

declare(strict_types = 1);

namespace Tests\Unit\Secrets;

use Illuminate\Log\Logger;
use Monolog\Formatter\JsonFormatter;
use Monolog\Formatter\LineFormatter;
use Monolog\Handler\TestHandler;
use Monolog\Logger as Monolog;
use Monolog\LogRecord;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use SineMacula\Laravel\Mfa\Secrets\RedactSecrets;
use SineMacula\Laravel\Mfa\Secrets\RedactSecretsInLogs;
use Tests\Fixtures\Secrets\AddsCodeToExtra;
use Tests\Fixtures\Secrets\Enums\RefusingCase;
use Tests\Fixtures\Secrets\RefusesToBeLogged;
use Tests\Fixtures\Secrets\SerializingException;

/**
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RedactSecretsInLogs::class)]
final class RedactSecretsInLogsTest extends TestCase
{
    /**
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
     * The logger's own processors keep their order.
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
     * With the value as its class alone.
     *
     * @return void
     */
    public function testWritesARecordHoldingAValueThatRefusesToBeLogged(): void
    {
        $handler = new TestHandler;
        $monolog = new Monolog('mfa', [$handler]);

        (new RedactSecretsInLogs)(new Logger($monolog));

        $monolog->info('Secret issued.', ['issued' => new RefusesToBeLogged]);

        self::assertSame([RefusesToBeLogged::class => '[unserializable]'], $handler->getRecords()[0]->context['issued'] ?? null);
    }

    /**
     * As its own JSON form redacted, or its class when that throws, so neither
     * formatter throws or writes the code.
     *
     * @return void
     */
    public function testLogsTheOwnFormOfAnExceptionOrAnEnumRedacted(): void
    {
        foreach ([new JsonFormatter, new LineFormatter] as $formatter) {

            $handler = new TestHandler;

            $handler->setFormatter($formatter);

            $monolog = new Monolog('mfa', [$handler]);

            (new RedactSecretsInLogs)(new Logger($monolog));

            $monolog->error('Delivery failed.', ['exception' => new SerializingException, 'refused' => new SerializingException(true), 'nested' => [RefusingCase::HELD]]);
            $record = $handler->getRecords()[0];

            self::assertSame([SerializingException::class => ['code' => '[redacted]', 'label' => 'Phone']], $record->context['exception'] ?? null);
            self::assertSame([SerializingException::class => '[unserializable]'], $record->context['refused'] ?? null);
            self::assertSame([[RefusingCase::class => '[unserializable]']], $record->context['nested'] ?? null);
            self::assertIsString($record->formatted);
            self::assertStringNotContainsString(SerializingException::CODE, $record->formatted);
        }
    }

    /**
     * However many it had and however often it is tapped.
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
     * @return void
     */
    public function testLeavesOtherLoggersAlone(): void
    {
        $logger = new Logger(new NullLogger);

        (new RedactSecretsInLogs)($logger);

        self::assertInstanceOf(NullLogger::class, $logger->getLogger());
    }
}
