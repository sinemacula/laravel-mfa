<?php

declare(strict_types = 1);

namespace Tests\Unit\Codes;

use Illuminate\Config\Repository;
use Illuminate\Mail\SendQueuedMailable;
use Illuminate\Queue\Events\JobExceptionOccurred;
use Illuminate\Queue\Jobs\SyncJob;
use Illuminate\Queue\Worker;
use Illuminate\Queue\WorkerOptions;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Mail;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Mfa\Codes\MailEmailSender;
use SineMacula\Laravel\Mfa\Codes\MfaCodeMessage;
use SineMacula\Laravel\Mfa\Secrets\ExceptionScrubber;
use Tests\Fixtures\Codes\FailingTransport;
use Tests\Fixtures\Codes\PayloadRecordingQueue;
use Tests\Fixtures\Secrets\RecordedTrace;
use Tests\TestCase;

/**
 * Tests that a failure while `MfaCodeMessage` is sent, at once or by a queue
 * worker running it from the queue, leaves `send()` scrubbed of the code and
 * the recipient's address, before the worker reports it or any listener sees
 * it, whether or not PHP recorded the arguments, and that nothing collected for
 * one message is carried to the next.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(MfaCodeMessage::class)]
final class MfaCodeMessageFailureTest extends TestCase
{
    /** @var string A code the failure must not show. */
    private const string CODE = '493817';

    /** @var string The address the code is sent to. */
    private const string ADDRESS = 'ada@example.test';

    /**
     * Rows of whether PHP records the arguments of each call in a trace, as a
     * development configuration does, or ignores them, as a production one
     * does.
     *
     * @return iterable<string, array{bool}>
     */
    public static function traceArguments(): iterable
    {
        yield 'arguments recorded' => [true];
        yield 'arguments ignored' => [false];
    }

    /**
     * A queued message the worker fails to send leaves the worker scrubbed of
     * its code and its recipient, in every message and frame of the chain, and
     * already scrubbed when the worker's exception event is dispatched.
     *
     * @param  bool  $arguments
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[DataProvider('traceArguments')]
    public function testAQueuedMessageAWorkerFailsToSendIsScrubbed(bool $arguments): void
    {
        $this->failMail();

        $seen = null;

        Event::listen(JobExceptionOccurred::class, static function (JobExceptionOccurred $event) use (&$seen): void {
            $seen = $event->exception->getMessage() . $event->exception->getTraceAsString();
        });

        $exception = RecordedTrace::thrownBy(fn () => $this->work(self::CODE, self::ADDRESS), $arguments);

        self::assertSame('The relay refused the message to [redacted].', $exception->getMessage());
        self::assertIsString($seen);
        self::assertStringNotContainsString(self::CODE, $seen);
        self::assertStringNotContainsString(self::ADDRESS, $seen);
        $this->assertScrubbed($exception, self::CODE, self::ADDRESS);
    }

    /**
     * A message the sender fails to send at once is scrubbed the same way.
     *
     * @param  bool  $arguments
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[DataProvider('traceArguments')]
    public function testAMessageThatFailsToSendAtOnceIsScrubbed(bool $arguments): void
    {
        $this->failMail();

        $sender = $this->container()->make(MailEmailSender::class);

        $exception = RecordedTrace::thrownBy(static fn () => $sender->send(self::ADDRESS, new MfaCodeMessage(self::CODE, 10)), $arguments);

        self::assertSame('The relay refused the message to [redacted].', $exception->getMessage());
        $this->assertScrubbed($exception, self::CODE, self::ADDRESS);
    }

    /**
     * Each job is scrubbed of its own message's code and recipient, and what
     * was collected for one job is not kept for the next or for any later
     * exception.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testNothingIsCarriedFromOneJobToTheNext(): void
    {
        $this->failMail();

        $first  = RecordedTrace::thrownBy(fn () => $this->work(self::CODE, self::ADDRESS));
        $second = RecordedTrace::thrownBy(fn () => $this->work('618204', 'bob@example.test'));

        $this->assertScrubbed($first, self::CODE, self::ADDRESS);
        $this->assertScrubbed($second, '618204', 'bob@example.test');

        $later = new \RuntimeException('Unrelated failure mentioning ' . self::CODE . ' and ' . self::ADDRESS . '.');

        ExceptionScrubber::scrub($later);

        self::assertSame('Unrelated failure mentioning ' . self::CODE . ' and ' . self::ADDRESS . '.', $later->getMessage());
    }

    /**
     * Have the default mailer refuse every message.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function failMail(): void
    {
        $config = $this->container()->make(Repository::class);

        $config->set('mail.mailers.failing', ['transport' => 'failing']);
        $config->set('mail.default', 'failing');
        $config->set('mail.from', ['address' => 'no-reply@example.test', 'name' => 'Example']);

        Mail::extend('failing', static fn (): FailingTransport => new FailingTransport);
    }

    /**
     * Queue a message carrying the code to the address, encrypted as a queue
     * stores it, and have a queue worker run it.
     *
     * @param  string  $code
     * @param  string  $address
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Throwable
     */
    private function work(string $code, string $address): void
    {
        $queue = new PayloadRecordingQueue;
        $queue->setContainer($this->container());

        $payload = $queue->payloadFor(new SendQueuedMailable((new MfaCodeMessage($code, 10))->to($address)));

        self::assertStringNotContainsString($code, $payload);

        $worker = $this->container()->make('queue.worker');

        self::assertInstanceOf(Worker::class, $worker);

        $worker->process('sync', new SyncJob($this->container(), $payload, 'sync', 'default'), new WorkerOptions);
    }

    /**
     * Assert that no message and no frame of any exception in the chain shows
     * the code or the address, and that no frame keeps a code message.
     *
     * @param  \Throwable  $exception
     * @param  string  $code
     * @param  string  $address
     * @return void
     */
    private function assertScrubbed(\Throwable $exception, string $code, string $address): void
    {
        for ($current = $exception; $current !== null; $current = $current->getPrevious()) {
            foreach ([$code, $address] as $plaintext) {
                self::assertStringNotContainsString($plaintext, $current->getMessage());
                self::assertStringNotContainsString($plaintext, $current->getTraceAsString());

                foreach (RecordedTrace::strings($current) as $string) {
                    self::assertStringNotContainsString($plaintext, $string);
                }
            }

            foreach ($current->getTrace() as $frame) {
                array_walk_recursive($frame, static function (mixed $value): void {
                    self::assertNotInstanceOf(MfaCodeMessage::class, $value);
                    self::assertNotInstanceOf(SendQueuedMailable::class, $value);
                });
            }
        }

        self::assertNotNull($exception->getPrevious());
    }
}
