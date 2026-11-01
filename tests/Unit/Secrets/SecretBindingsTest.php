<?php

declare(strict_types = 1);

namespace Tests\Unit\Secrets;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Container\Container;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Events\Dispatcher;
use Illuminate\Foundation\Exceptions\Handler;
use Illuminate\Routing\Router;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\Secrets\NoStore;
use SineMacula\Laravel\Mfa\Secrets\RedactSecretsInLogs;
use SineMacula\Laravel\Mfa\Secrets\SecretBindings;
use Symfony\Component\HttpFoundation\Response;
use Tests\Fixtures\Secrets\ForgedTrace;

/**
 * Tests for `SecretBindings`: the middleware is aliased, and while redaction
 * is on every log channel is tapped and every reported exception scrubbed.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SecretBindings::class)]
final class SecretBindingsTest extends TestCase
{
    /** @var string A delivered code. */
    private const string CODE = '482915';

    /** @var string A tap of the application's own. */
    private const string APPLICATION_TAP = 'App\Logging\CustomizeFormatter';

    /**
     * The middleware is aliased as `mfa.no-store`.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAliasesTheNoStoreMiddleware(): void
    {
        $container = $this->container(true);

        SecretBindings::boot($container);

        self::assertSame(['mfa.no-store' => NoStore::class], $container->make(Router::class)->getMiddleware());
    }

    /**
     * Every configured log channel is given the tap, after its own taps.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testTapsEveryLogChannel(): void
    {
        $container = $this->container(true, [
            'single' => ['driver' => 'single'],
            'daily'  => ['driver' => 'daily', 'tap' => [self::APPLICATION_TAP]],
        ]);

        SecretBindings::boot($container);

        self::assertSame([
            'single' => ['driver' => 'single', 'tap' => [RedactSecretsInLogs::class]],
            'daily'  => ['driver' => 'daily', 'tap' => [self::APPLICATION_TAP, RedactSecretsInLogs::class]],
        ], $this->config($container)->get('logging.channels'));
    }

    /**
     * A channel that lists the tap already is not given it again.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testTapsAChannelOnce(): void
    {
        $container = $this->container(true, ['single' => ['driver' => 'single', 'tap' => [RedactSecretsInLogs::class, self::APPLICATION_TAP]]]);

        SecretBindings::boot($container);
        SecretBindings::boot($container);

        self::assertSame(
            ['single' => ['driver' => 'single', 'tap' => [RedactSecretsInLogs::class, self::APPLICATION_TAP]]],
            $this->config($container)->get('logging.channels'),
        );
    }

    /**
     * A channel that is not an array, or whose taps are not a list, is left as
     * it is.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testLeavesMalformedChannelsAlone(): void
    {
        $channels  = ['named' => 'single', 'tapped' => ['driver' => 'single', 'tap' => self::APPLICATION_TAP]];
        $container = $this->container(true, $channels);

        SecretBindings::boot($container);

        self::assertSame($channels, $this->config($container)->get('logging.channels'));
    }

    /**
     * Without log channels, the logging configuration is left as it is.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testLeavesTheConfigurationAloneWithoutLogChannels(): void
    {
        $container = $this->container(true, null);

        SecretBindings::boot($container);

        self::assertFalse($this->config($container)->has('logging.channels'));
    }

    /**
     * With redaction off, no channel is tapped, but the middleware is still
     * aliased.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testLeavesLogsAloneWhenRedactionIsOff(): void
    {
        $container = $this->container(false, ['single' => ['driver' => 'single']]);

        SecretBindings::boot($container);

        self::assertSame(['single' => ['driver' => 'single']], $this->config($container)->get('logging.channels'));
        self::assertArrayHasKey('mfa.no-store', $container->make(Router::class)->getMiddleware());
    }

    /**
     * An exception handler built after the package boots scrubs every
     * exception it reports before its later reporters see it.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Throwable
     */
    public function testScrubsReportsOfAHandlerBuiltLater(): void
    {
        $container = $this->container(true);

        SecretBindings::boot($container);

        $this->bindHandler($container);

        $trace = $this->reportedTrace($container);

        self::assertStringNotContainsString(self::CODE, $trace);
        self::assertStringContainsString('[redacted]', $trace);
    }

    /**
     * An exception handler built before the package boots scrubs every
     * exception it reports too.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Throwable
     */
    public function testScrubsReportsOfAHandlerBuiltAlready(): void
    {
        $container = $this->container(true);

        $this->bindHandler($container);

        $container->make(ExceptionHandler::class);

        SecretBindings::boot($container);

        self::assertStringNotContainsString(self::CODE, $this->reportedTrace($container));
    }

    /**
     * With redaction off, reported exceptions are not scrubbed.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Throwable
     */
    public function testLeavesReportsAloneWhenRedactionIsOff(): void
    {
        $container = $this->container(false);

        SecretBindings::boot($container);

        $this->bindHandler($container);

        self::assertStringContainsString(self::CODE, $this->reportedTrace($container));
    }

    /**
     * An exception handler other than Laravel's is left as it is.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testLeavesAnotherExceptionHandlerAlone(): void
    {
        $container = $this->container(true);
        $handler   = new class implements ExceptionHandler {
            /** @var int How many exceptions were reported. */
            public int $reported = 0;

            /**
             * Count the report.
             *
             * @param  \Throwable  $e
             * @return void
             */
            #[\Override]
            public function report(\Throwable $e): void
            {
                $this->reported++;
            }

            /**
             * Report everything.
             *
             * @param  \Throwable  $e
             * @return bool
             */
            #[\Override]
            public function shouldReport(\Throwable $e): bool
            {
                return true;
            }

            /**
             * Render nothing.
             *
             * @param  mixed  $request
             * @param  \Throwable  $e
             * @return \Symfony\Component\HttpFoundation\Response
             */
            #[\Override]
            public function render(mixed $request, \Throwable $e): Response
            {
                return new Response;
            }

            /**
             * Render nothing.
             *
             * @param  mixed  $output
             * @param  \Throwable  $e
             * @return void
             */
            #[\Override]
            public function renderForConsole(mixed $output, \Throwable $e): void {}
        };

        $container->instance(ExceptionHandler::class, $handler);

        SecretBindings::boot($container);

        self::assertSame($handler, $container->make(ExceptionHandler::class));
        self::assertSame(0, $handler->reported);
    }

    /**
     * A container holding the configuration and a router.
     *
     * @param  bool  $redact
     * @param  ?array<array-key, mixed>  $channels
     * @return \Illuminate\Container\Container
     */
    private function container(bool $redact, ?array $channels = []): Container
    {
        $container = new Container;
        $config    = ['mfa' => ['secrets' => ['redact' => $redact]]];

        if ($channels !== null) {
            $config['logging'] = ['channels' => $channels];
        }

        $container->instance(Repository::class, new ConfigRepository($config));
        $container->instance(Router::class, new Router(new Dispatcher($container), $container));

        return $container;
    }

    /**
     * The container's configuration.
     *
     * @param  \Illuminate\Container\Container  $container
     * @return \Illuminate\Contracts\Config\Repository
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function config(Container $container): Repository
    {
        /** @var \Illuminate\Contracts\Config\Repository */
        return $container->make(Repository::class);
    }

    /**
     * Bind Laravel's exception handler.
     *
     * @param  \Illuminate\Container\Container  $container
     * @return void
     */
    private function bindHandler(Container $container): void
    {
        $container->singleton(ExceptionHandler::class, static fn (Container $app): Handler => new Handler($app));
    }

    /**
     * Report an exception whose trace holds a code passed into the package,
     * and return its trace as a reporter registered after the package's sees
     * it.
     *
     * @param  \Illuminate\Container\Container  $container
     * @return string
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Throwable
     */
    private function reportedTrace(Container $container): string
    {
        $handler = $container->make(ExceptionHandler::class);

        self::assertInstanceOf(Handler::class, $handler);

        $trace = '';

        $handler->reportable(static function (\Throwable $throwable) use (&$trace): bool {
            $trace = $throwable->getTraceAsString();

            return false;
        });

        $handler->report(ForgedTrace::onto(new \RuntimeException('Verification failed.'), [
            ['file' => '/app/Http/Controllers/VerifyController.php', 'line' => 12, 'class' => Mfa::class, 'type' => '::', 'function' => 'verify', 'args' => [self::CODE]],
        ]));

        return $trace;
    }
}
