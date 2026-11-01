<?php

declare(strict_types = 1);

namespace Tests\Unit\Config;

use Illuminate\Config\Repository;
use Illuminate\Contracts\Foundation\Application;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Config\ConfigurationBindings;
use SineMacula\Laravel\Mfa\Config\ConfigurationValidator;
use SineMacula\Laravel\Mfa\Exceptions\InvalidConfigurationException;
use Tests\TestCase;

/**
 * Unit tests for `ConfigurationBindings`: the configuration is checked once the
 * application has booted, unless `mfa:check` is the console command running,
 * and on demand.
 *
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
     * Put the console arguments back.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $_SERVER['argv'] = $this->argv;

        parent::tearDown();
    }

    /**
     * Validating passes the shipped configuration and refuses a setting out of
     * range, listing it.
     *
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
     * Once the application has booted, a misconfiguration fails.
     *
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
     * While `mfa:check` runs, the boot check is skipped so the command can
     * report the problems itself.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testBootSkipsTheCheckWhileTheCheckCommandRuns(): void
    {
        $this->container()->make(Repository::class)->set('mfa.totp.window', 9);

        $_SERVER['argv'] = ['artisan', 'mfa:check'];

        ConfigurationBindings::boot($this->container());

        $_SERVER['argv'] = ['artisan', 'migrate'];

        $this->expectException(InvalidConfigurationException::class);

        ConfigurationBindings::boot($this->container());
    }

    /**
     * Outside the console, the boot check runs whatever the arguments say.
     *
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
