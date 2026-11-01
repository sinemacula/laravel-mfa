<?php

declare(strict_types = 1);

namespace Tests\Integration\Secrets;

use Illuminate\Config\Repository;
use Illuminate\Log\Logger;
use Illuminate\Log\LogManager;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Context;
use Monolog\Formatter\JsonFormatter;
use Monolog\Formatter\LineFormatter;
use Monolog\Handler\TestHandler;
use Monolog\Logger as Monolog;
use Monolog\LogRecord;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Contracts\FactorDriver;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\Secrets\ExceptionScrubber;
use SineMacula\Laravel\Mfa\Secrets\Redactor;
use SineMacula\Laravel\Mfa\Secrets\RedactSecrets;
use SineMacula\Laravel\Mfa\Secrets\RedactSecretsInLogs;
use SineMacula\Laravel\Mfa\Secrets\RevealedSecret;
use SineMacula\Laravel\Mfa\Secrets\SecretBindings;
use Tests\Fixtures\Factors\InMemoryFactor;
use Tests\Fixtures\Identities\TestUser;
use Tests\Fixtures\Secrets\AddsCodeToExtra;
use Tests\Fixtures\Secrets\CodeForwardingDriver;
use Tests\Fixtures\Secrets\RecordedTrace;
use Tests\Fixtures\Secrets\SecretCarryingException;
use Tests\TestCase;

/**
 * Tests that secrets, codes and full destinations never reach a log through the
 * application's own channels: in a log's context, objects in it included, in
 * Laravel's shared context, in what a channel's processors add, in a reported
 * exception's context and message, and in a trace's arguments.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SecretBindings::class)]
#[CoversClass(RedactSecretsInLogs::class)]
#[CoversClass(RedactSecrets::class)]
#[CoversClass(Redactor::class)]
#[CoversClass(ExceptionScrubber::class)]
final class LogRedactionTest extends TestCase
{
    /** @var string A TOTP secret. */
    private const string SECRET = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP';

    /** @var string A delivered code. */
    private const string CODE = '482915';

    /** @var string A destination codes are sent to. */
    private const string DESTINATION = '+447700900123';

    /**
     * Secrets, codes and destinations in a log's context are redacted, and the
     * rest of the context is kept.
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
     * A code in Laravel's shared context, which every log carries, is redacted.
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
     * A code passed through the facade, into the package and on to a driver
     * outside it, is scrubbed from every frame of a reported exception's trace,
     * the facade's and the driver's included, before it is logged.
     *
     * @return void
     */
    public function testScrubsACodePassedThroughTheFacadeFromAReportedException(): void
    {
        $exception = $this->exceptionPassingTheCode();

        self::assertContains(self::CODE, RecordedTrace::strings($exception));

        report($exception);

        self::assertNotContains(self::CODE, RecordedTrace::strings($exception));
        self::assertStringNotContainsString(self::CODE, $exception->getTraceAsString());
        self::assertSame($exception, $this->lastRecord()->context['exception'] ?? null);
    }

    /**
     * A code recorded in the trace of an exception logged directly is scrubbed
     * too.
     *
     * @return void
     */
    public function testScrubsTheTraceOfALoggedException(): void
    {
        $exception = $this->exceptionPassingTheCode();

        $this->logger()->error('Verification failed.', ['exception' => $exception]);

        self::assertNotContains(self::CODE, RecordedTrace::strings($exception));
        self::assertStringNotContainsString(self::CODE, $exception->getTraceAsString());
    }

    /**
     * A provisioning URI in the message of a logged exception, or of a previous
     * one, never reaches the written record.
     *
     * @return void
     */
    public function testRedactsProvisioningUrisInLoggedExceptionMessages(): void
    {
        $uri       = 'otpauth://totp/Acme:ben?secret=' . self::SECRET;
        $exception = new \RuntimeException('Rendering ' . $uri . ' failed.', 0, new \InvalidArgumentException('Bad data: ' . $uri));

        $this->logger()->error('Enrolment failed.', ['exception' => $exception]);

        $written = (new JsonFormatter)->format($this->lastRecord());

        self::assertStringNotContainsString(self::SECRET, $written);
        self::assertStringContainsString('Rendering [redacted] failed.', $written);
        self::assertStringContainsString('Bad data: [redacted]', $written);
    }

    /**
     * Secrets held in objects in a log's context, a plain object and a
     * collection, never reach the written record.
     *
     * @return void
     */
    public function testRedactsSecretsHeldInObjects(): void
    {
        $this->logger()->info('Enrolment started.', [
            'factor' => (object) ['type' => 'sms', 'destination' => self::DESTINATION, 'secret' => self::SECRET],
            'codes'  => new Collection([new RevealedSecret(self::CODE), self::CODE]),
            'items'  => new Collection([['code' => self::CODE, 'label' => 'Phone']]),
        ]);

        $written = (new LineFormatter)->format($this->lastRecord());

        self::assertStringNotContainsString(self::DESTINATION, $written);
        self::assertStringNotContainsString(self::SECRET, $written);
        self::assertStringContainsString('Phone', $written);
        self::assertStringContainsString('"type":"sms"', $written);
    }

    /**
     * A recursive context is truncated rather than walked without end.
     *
     * @return void
     */
    public function testTruncatesARecursiveContext(): void
    {
        $context         = ['code' => self::CODE];
        $context['self'] = &$context;

        $this->logger()->info('Recursive.', ['data' => $context]);

        $written = (new LineFormatter)->format($this->lastRecord());

        self::assertStringNotContainsString(self::CODE, $written);
    }

    /**
     * What a channel's own processors add to a record is redacted, since the
     * redaction runs after them.
     *
     * @return void
     */
    public function testRedactsWhatAChannelsOwnProcessorsAdd(): void
    {
        $this->logger('enriched')->info('Code checked.');

        self::assertSame('[redacted]', $this->lastRecord('enriched')->extra['code'] ?? null);
    }

    /**
     * A channel resolved before the package boots is tapped as it boots, so its
     * records are redacted for the rest of the process.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testTapsAChannelResolvedBeforeBoot(): void
    {
        /** @var \Illuminate\Config\Repository $config */
        $config = $this->container()->make(Repository::class);

        $config->set('logging.channels.early', ['driver' => 'monolog', 'handler' => TestHandler::class]);

        $this->logger('early')->info('Code sent.', ['code' => self::CODE]);

        self::assertSame(['code' => self::CODE], $this->lastRecord('early')->context);

        SecretBindings::boot($this->container());

        $this->logger('early')->info('Code sent.', ['code' => self::CODE]);

        self::assertSame(['code' => '[redacted]'], $this->lastRecord('early')->context);
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
     * Log through a test channel, through a stack of it, both recorded by one
     * test handler, and through a channel with a processor of its own.
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
        $config->set('logging.channels.enriched', ['driver' => 'monolog', 'handler' => TestHandler::class, 'processors' => [AddsCodeToExtra::class]]);
    }

    /**
     * The exception thrown below a call through the facade, which hands the
     * code into the package and on to a driver outside it.
     *
     * @return \Throwable
     *
     * @throws \LogicException
     */
    private function exceptionPassingTheCode(): \Throwable
    {
        $user = TestUser::query()->create(['email' => 'secrets@example.com']);

        $this->actingAs($user);

        Mfa::extend('forwarding', static fn (): FactorDriver => new CodeForwardingDriver);

        $factor = new InMemoryFactor(type: 'forwarding', authenticatable: $user);

        return RecordedTrace::thrownBy(static fn (): bool => Mfa::verify('forwarding', $factor, self::CODE));
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
     * The last record a channel's test handler recorded.
     *
     * @param  string  $channel
     * @return \Monolog\LogRecord
     */
    private function lastRecord(string $channel = 'secrets'): LogRecord
    {
        $handler = $this->monolog($channel)->getHandlers()[0] ?? null;

        self::assertInstanceOf(TestHandler::class, $handler);

        $records = $handler->getRecords();
        $record  = end($records);

        self::assertInstanceOf(LogRecord::class, $record);

        return $record;
    }
}
