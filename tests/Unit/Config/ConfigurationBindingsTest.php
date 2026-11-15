<?php

declare(strict_types = 1);

namespace Tests\Unit\Config;

use Illuminate\Config\Repository;
use Illuminate\Console\Events\CommandStarting;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Queue\Events\WorkerStarting;
use Illuminate\Queue\WorkerOptions;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Mfa\Config\ConfigurationBindings;
use SineMacula\Laravel\Mfa\Config\ConfigurationValidator;
use SineMacula\Laravel\Mfa\Exceptions\InvalidConfigurationException;
use Symfony\Component\Console\Input\ArrayInput;
use Symfony\Component\Console\Output\NullOutput;
use Tests\TestCase;

/**
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ConfigurationBindings::class)]
final class ConfigurationBindingsTest extends TestCase
{
    /**
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testValidateChecksTheConfiguration(): void
    {
        ConfigurationBindings::validate($this->container());

        $this->container()->make(Repository::class)->set('mfa.codes.length', 5);

        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessage('[codes] mfa.codes.length must be an integer from 6 to 10.');

        ConfigurationBindings::validate($this->container());
    }

    /**
     * In the console nothing is checked at boot, so any command can run.
     *
     * @return void
     */
    public function testTheConsoleBootsWithoutTheCheck(): void
    {
        $this->container()->make(Repository::class)->set('mfa.totp.window', 9);

        ConfigurationBindings::boot($this->container());

        $this->addToAssertionCount(1);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function workerCommands(): iterable
    {
        $commands = [
            'queue:work', 'queue:listen', 'horizon', 'horizon:supervisor', 'horizon:work', 'schedule:run',
            'schedule:work', 'schedule:test', 'octane:start', 'octane:frankenphp', 'octane:roadrunner', 'octane:swoole',
        ];

        foreach ($commands as $command) {
            yield $command => [$command];
        }
    }

    /**
     * @param  string  $command
     * @return void
     */
    #[DataProvider('workerCommands')]
    public function testAWorkerIsCheckedAsItStarts(string $command): void
    {
        $this->container()->make(Repository::class)->set('mfa.totp.window', 9);

        ConfigurationBindings::boot($this->container());

        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessage('[totp] mfa.totp.window must be an integer from 0 to 3.');

        $this->start($command);
    }

    /**
     * A queue worker started through another command's call() is checked too.
     *
     * @return void
     */
    public function testAQueueWorkerIsCheckedAsItStarts(): void
    {
        $this->container()->make(Repository::class)->set('mfa.totp.window', 9);

        ConfigurationBindings::boot($this->container());

        $this->expectException(InvalidConfigurationException::class);

        $this->container()->make(Dispatcher::class)->dispatch(new WorkerStarting('sync', 'default', new WorkerOptions));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function otherCommands(): iterable
    {
        foreach (['mfa:check', 'iam:check', 'migrate', 'config:cache', 'tinker'] as $command) {
            yield $command => [$command];
        }
    }

    /**
     * @param  string  $command
     * @return void
     */
    #[DataProvider('otherCommands')]
    public function testAnyOtherCommandStartsUnchecked(string $command): void
    {
        $this->container()->make(Repository::class)->set('mfa.totp.window', 9);

        ConfigurationBindings::boot($this->container());

        $this->start($command);

        $this->addToAssertionCount(1);
    }

    /**
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testBootChecksOutsideTheConsole(): void
    {
        $config = new Repository($this->container()->make(Repository::class)->all());
        $config->set('mfa.codes.ttl_minutes', 11);

        $app = \Mockery::mock(Application::class);
        $app->shouldReceive('runningInConsole')->andReturnFalse();
        $app->shouldReceive('make')->with(ConfigurationValidator::class)->andReturn(new ConfigurationValidator($this->container(), $config));
        $app->shouldReceive('booted')->once()->andReturnUsing(static function (\Closure $callback) use ($app): void {
            $callback($app);
        });

        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessage('[codes] mfa.codes.ttl_minutes must be an integer from 1 to 10.');

        ConfigurationBindings::boot($app);
    }

    /**
     * @param  string  $command
     * @return void
     */
    private function start(string $command): void
    {
        $this->container()->make(Dispatcher::class)->dispatch(new CommandStarting($command, new ArrayInput([]), new NullOutput));
    }
}
