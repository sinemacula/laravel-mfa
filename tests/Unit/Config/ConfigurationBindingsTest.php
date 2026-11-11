<?php

declare(strict_types = 1);

namespace Tests\Unit\Config;

use Illuminate\Config\Repository;
use Illuminate\Contracts\Foundation\Application;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Mfa\Config\ConfigurationBindings;
use SineMacula\Laravel\Mfa\Config\ConfigurationValidator;
use SineMacula\Laravel\Mfa\Exceptions\InvalidConfigurationException;
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
    /** @var array<array-key, mixed> The console arguments before the test. */
    private array $argv = [];

    /**
     * Keep the console arguments, which some tests change.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $argv = $_SERVER['argv'] ?? [];

        $this->argv = is_array($argv) ? $argv : [];
    }

    /**
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $_SERVER['argv'] = $this->argv;

        parent::tearDown();
    }

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
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testBootChecksTheConfigurationOnceBooted(): void
    {
        $this->container()->make(Repository::class)->set('mfa.totp.window', 9);

        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessage('[totp] mfa.totp.window must be an integer from 0 to 3.');

        ConfigurationBindings::boot($this->container());
    }

    /**
     * `mfa:check` behind any option, and the commands that list, describe,
     * discover, cache or clear configuration.
     *
     * @return iterable<string, array{list<string>}>
     */
    public static function uncheckedCommands(): iterable
    {
        yield 'mfa:check' => [['artisan', 'mfa:check']];
        yield 'mfa:check behind a flag' => [['artisan', '-v', 'mfa:check']];
        yield 'mfa:check behind an option with its value' => [['artisan', '--env=production', 'mfa:check']];
        yield 'config:cache' => [['artisan', 'config:cache']];
        yield 'config:clear' => [['artisan', 'config:clear']];
        yield 'config:show' => [['artisan', 'config:show', 'mfa']];
        yield 'help' => [['artisan', 'help', 'mfa:check']];
        yield 'list' => [['artisan', 'list']];
        yield 'optimize:clear' => [['artisan', 'optimize:clear']];
        yield 'package:discover' => [['artisan', 'package:discover', '--ansi']];
    }

    /**
     * So the command can report the problems itself, or a bad cached
     * configuration can be cleared.
     *
     * @param  list<string>  $argv
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[DataProvider('uncheckedCommands')]
    public function testBootSkipsTheCheckWhileAnUncheckedCommandRuns(array $argv): void
    {
        $this->container()->make(Repository::class)->set('mfa.totp.window', 9);

        $_SERVER['argv'] = $argv;

        ConfigurationBindings::boot($this->container());

        $this->addToAssertionCount(1);
    }

    /**
     * Including one that only mentions a skipped command as an argument, and
     * none.
     *
     * @return iterable<string, array{list<string>}>
     */
    public static function checkedCommands(): iterable
    {
        yield 'migrate' => [['artisan', 'migrate']];
        yield 'a skipped command as a later argument' => [['artisan', 'queue:work', 'mfa:check']];
        yield 'an option alone' => [['artisan', '--version']];
        yield 'no command' => [['artisan']];
    }

    /**
     * @param  list<string>  $argv
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[DataProvider('checkedCommands')]
    public function testBootChecksWhileAnyOtherCommandRuns(array $argv): void
    {
        $this->container()->make(Repository::class)->set('mfa.totp.window', 9);

        $_SERVER['argv'] = $argv;

        $this->expectException(InvalidConfigurationException::class);

        ConfigurationBindings::boot($this->container());
    }

    /**
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testBootChecksOutsideTheConsole(): void
    {
        $_SERVER['argv'] = ['artisan', 'mfa:check'];

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
}
