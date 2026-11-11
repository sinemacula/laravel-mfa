<?php

declare(strict_types = 1);

namespace Tests\Integration\Octane\Concerns;

use Illuminate\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Testing\TestResponse;
use Laravel\Octane\ApplicationFactory;
use Laravel\Octane\Events\RequestTerminated;
use Laravel\Octane\Octane;
use Laravel\Octane\OctaneServiceProvider;
use Laravel\Octane\RequestContext;
use Laravel\Octane\Testing\Fakes\FakeClient;
use Laravel\Octane\Testing\Fakes\FakeWorker;
use Symfony\Component\HttpFoundation\Response;

/**
 * Serves requests through Octane's real `Worker` and listeners over the test's
 * booted application, as Octane's own suite does; only the server is fake.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait ServesRequestsThroughOctane
{
    /** @var ?\Laravel\Octane\Testing\Fakes\FakeWorker Serves every request. */
    private ?FakeWorker $octaneWorker = null;

    /** @var ?\Laravel\Octane\Testing\Fakes\FakeClient The fake server the worker answers. */
    private ?FakeClient $octaneClient = null;

    /**
     * @return void
     */
    protected function bootOctaneWorker(): void
    {
        $app = $this->octaneApplication();

        $app->register(OctaneServiceProvider::class);

        $this->octaneClient = new FakeClient([]);
        $this->octaneWorker = new FakeWorker($this->bootedApplicationFactory($app), $this->octaneClient);

        $this->octaneWorker->boot();
    }

    /**
     * Fails the test when the worker caught an error.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Testing\TestResponse<\Symfony\Component\HttpFoundation\Response>
     */
    protected function serve(Request $request): TestResponse
    {
        $worker = $this->octaneWorker;
        $client = $this->octaneClient;

        self::assertNotNull($worker, 'Boot the Octane worker before serving a request.');
        self::assertNotNull($client);

        $errors    = count($client->errors);
        $responses = count($client->responses);

        $worker->handle($request, new RequestContext(['request' => $request]));

        self::assertSame([], array_slice($client->errors, $errors), 'The Octane worker caught an error.');
        self::assertCount($responses + 1, $client->responses);

        $response = $client->responses[$responses];

        $this->restoreRootApplication($request, $response);

        return TestResponse::fromBaseResponse($response);
    }

    /**
     * Warms the booted application instead of bootstrapping a skeleton.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @return \Laravel\Octane\ApplicationFactory
     */
    private function bootedApplicationFactory(Application $app): ApplicationFactory
    {
        $warmer  = new ApplicationFactory($app->basePath());
        $factory = \Mockery::mock(ApplicationFactory::class);

        $factory->shouldReceive('createApplication')->andReturnUsing(static function (array $initialInstances = []) use ($app, $warmer): Application {

            foreach ($initialInstances as $abstract => $instance) {
                $app->instance((string) $abstract, $instance);
            }

            return $warmer->warm($app, Octane::defaultServicesToWarm());
        });

        return $factory;
    }

    /**
     * Points services back at the root application so the test can read the
     * database between requests; nothing is reset, so isolation is Octane's.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Symfony\Component\HttpFoundation\Response  $response
     * @return void
     */
    private function restoreRootApplication(Request $request, Response $response): void
    {
        $app   = $this->octaneApplication();
        $event = new RequestTerminated($app, $app, $request, $response);

        foreach (Octane::prepareApplicationForNextOperation() as $listener) {

            if (!str_contains($listener, 'GiveNewApplicationInstanceTo')) {
                continue;
            }

            $app->make($listener)->handle($event);
        }
    }

    /**
     * @return \Illuminate\Foundation\Application
     */
    private function octaneApplication(): Application
    {
        $app = $this->app;

        self::assertInstanceOf(Application::class, $app);

        return $app;
    }
}
