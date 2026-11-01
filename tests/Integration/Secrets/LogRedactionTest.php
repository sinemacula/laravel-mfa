<?php

declare(strict_types = 1);

namespace Tests\Integration\Secrets;

use Illuminate\Config\Repository;
use Illuminate\Log\Logger;
use Illuminate\Log\LogManager;
use Illuminate\Support\Facades\Context;
use Monolog\Handler\TestHandler;
use Monolog\Logger as Monolog;
use Monolog\LogRecord;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\Secrets\RedactSecrets;
use SineMacula\Laravel\Mfa\Secrets\RedactSecretsInLogs;
use SineMacula\Laravel\Mfa\Secrets\RevealedSecret;
use SineMacula\Laravel\Mfa\Secrets\SecretBindings;
use Tests\Fixtures\Secrets\ForgedTrace;
use Tests\Fixtures\Secrets\SecretCarryingException;
use Tests\TestCase;

/**
 * Tests that secrets, codes and full destinations never reach a log through
 * the application's own channels: in a log's context, in Laravel's shared
 * context, in a reported exception's context, and in a trace's arguments.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SecretBindings::class)]
#[CoversClass(RedactSecretsInLogs::class)]
#[CoversClass(RedactSecrets::class)]
final class LogRedactionTest extends TestCase
{
    /** @var string A TOTP secret. */
    private const string SECRET = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP';

    /** @var string A delivered code. */
    private const string CODE = '482915';

    /** @var string A destination codes are sent to. */
    private const string DESTINATION = '+447700900123';

    /**
     * Secrets, codes and destinations in a log's context are redacted, and
     * the rest of the context is kept.
     *
     * @return void
     */
    public function testRedactsSecretsInALogsContext(): void
    {
        $this->logger()->info('Enrolment started.', [
            'secret' => self::SECRET,
            'factor' => ['type' => 'sms', 'destination' => self::DESTINATION],
            'shown'  => new RevealedSecret(self::SECRET),
            'label'  => 'Phone',
        ]);

        self::assertSame([
            'secret' => '[redacted]',
            'factor' => ['type' => 'sms', 'destination' => '[redacted]'],
            'shown'  => '[redacted]',
            'label'  => 'Phone',
        ], $this->lastRecord()->context);
    }

    /**
     * A provisioning URI in a log's message is redacted.
     *
     * @return void
     */
    public function testRedactsAProvisioningUriInALogsMessage(): void
    {
        $this->logger()->info('Provisioning otpauth://totp/Acme:ben?issuer=Acme&secret=' . self::SECRET);

        self::assertSame('Provisioning [redacted]', $this->lastRecord()->message);
    }

    /**
     * A code in Laravel's shared context, which every log carries, is
     * redacted.
     *
     * @return void
     */
    public function testRedactsSecretsInTheSharedContext(): void
    {
        Context::add('code', self::CODE);

        $this->logger()->info('Code sent.');

        self::assertSame('[redacted]', $this->lastRecord()->extra['code'] ?? null);
    }

    /**
     * The context of an exception the exception handler reports is redacted.
     *
     * @return void
     */
    public function testRedactsSecretsInAReportedExceptionsContext(): void
    {
        report(new SecretCarryingException(self::SECRET, self::CODE));

        $context = $this->lastRecord()->context;

        self::assertSame('[redacted]', $context['secret'] ?? null);
        self::assertSame('[redacted]', $context['code'] ?? null);
        self::assertSame('totp', $context['factor_type'] ?? null);
        self::assertInstanceOf(SecretCarryingException::class, $context['exception'] ?? null);
    }

    /**
     * A code passed into the package, recorded in the trace of a reported
     * exception, is scrubbed before the exception is logged.
     *
     * @return void
     */
    public function testScrubsTheTraceOfAReportedException(): void
    {
        $exception = $this->exceptionPassingTheCode();

        report($exception);

        self::assertStringNotContainsString(self::CODE, $exception->getTraceAsString());
        self::assertSame($exception, $this->lastRecord()->context['exception'] ?? null);
    }

    /**
     * A code recorded in the trace of an exception logged directly is
     * scrubbed too.
     *
     * @return void
     */
    public function testScrubsTheTraceOfALoggedException(): void
    {
        $exception = $this->exceptionPassingTheCode();

        $this->logger()->error('Verification failed.', ['exception' => $exception]);

        self::assertStringNotContainsString(self::CODE, $exception->getTraceAsString());
    }

    /**
     * Every configured channel is tapped, and a stack built from tapped
     * channels redacts once.
     *
     * @return void
     */
    public function testTapsEveryChannelAndRedactsOnceInAStack(): void
    {
        /** @var \Illuminate\Config\Repository $config */
        $config = $this->container()->make(Repository::class);

        self::assertContains(RedactSecretsInLogs::class, (array) $config->get('logging.channels.secrets.tap'));
        self::assertContains(RedactSecretsInLogs::class, (array) $config->get('logging.channels.everything.tap'));

        $redacting = array_filter($this->monolog('everything')->getProcessors(), static fn (mixed $processor): bool => $processor instanceof RedactSecrets);

        self::assertCount(1, $redacting);

        $this->logger('everything')->info('Code sent.', ['code' => self::CODE]);

        self::assertSame(['code' => '[redacted]'], $this->lastRecord()->context);
    }

    /**
     * Log through a test channel, and through a stack of it, both recorded by
     * one test handler.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        /** @var \Illuminate\Config\Repository $config */
        $config = app(Repository::class);

        $config->set('logging.default', 'secrets');
        $config->set('logging.channels.secrets', ['driver' => 'monolog', 'handler' => TestHandler::class]);
        $config->set('logging.channels.everything', ['driver' => 'stack', 'channels' => ['secrets']]);
    }

    /**
     * An exception whose trace records a code passed into the package.
     *
     * @return \RuntimeException
     */
    private function exceptionPassingTheCode(): \RuntimeException
    {
        return ForgedTrace::onto(new \RuntimeException('Verification failed.'), [
            ['file' => '/app/Http/Controllers/VerifyController.php', 'line' => 12, 'class' => Mfa::class, 'type' => '::', 'function' => 'verify', 'args' => ['totp', self::CODE]],
        ]);
    }

    /**
     * A channel's logger.
     *
     * @param  string  $channel
     * @return \Illuminate\Log\Logger
     */
    private function logger(string $channel = 'secrets'): Logger
    {
        $log = $this->container()->make('log');

        self::assertInstanceOf(LogManager::class, $log);

        $logger = $log->channel($channel);

        self::assertInstanceOf(Logger::class, $logger);

        return $logger;
    }

    /**
     * A channel's Monolog logger.
     *
     * @param  string  $channel
     * @return \Monolog\Logger
     */
    private function monolog(string $channel): Monolog
    {
        $monolog = $this->logger($channel)->getLogger();

        self::assertInstanceOf(Monolog::class, $monolog);

        return $monolog;
    }

    /**
     * The last record the test handler recorded.
     *
     * @return \Monolog\LogRecord
     */
    private function lastRecord(): LogRecord
    {
        $handler = $this->monolog('secrets')->getHandlers()[0] ?? null;

        self::assertInstanceOf(TestHandler::class, $handler);

        $records = $handler->getRecords();
        $record  = end($records);

        self::assertInstanceOf(LogRecord::class, $record);

        return $record;
    }
}
