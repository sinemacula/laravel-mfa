<?php

declare(strict_types = 1);

namespace Tests\Unit\Secrets;

use Illuminate\Log\Logger;
use Monolog\Logger as Monolog;
use Monolog\LogRecord;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use SineMacula\Laravel\Mfa\Secrets\RedactSecrets;
use SineMacula\Laravel\Mfa\Secrets\RedactSecretsInLogs;

/**
 * Tests for the `RedactSecretsInLogs` tap: the processor is pushed once onto
 * a Monolog logger, and any other logger is left as it is.
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
     * A logger that has the processor already is not given it again, whatever
     * other processors it has.
     *
     * @return void
     */
    public function testPushesTheProcessorOnce(): void
    {
        $other   = static fn (LogRecord $record): LogRecord => $record;
        $monolog = new Monolog('mfa', [], [$other, new RedactSecrets]);

        (new RedactSecretsInLogs)(new Logger($monolog));
        (new RedactSecretsInLogs)(new Logger($monolog));

        self::assertCount(2, $monolog->getProcessors());
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
