<?php

declare(strict_types = 1);

namespace Tests\Feature\Console;

use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Console\Kernel;
use Illuminate\Foundation\Testing\WithConsoleEvents;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Config\ConfigurationBindings;
use SineMacula\Laravel\Mfa\Exceptions\InvalidConfigurationException;
use Symfony\Component\Console\Input\ArrayInput;
use Symfony\Component\Console\Output\NullOutput;
use Tests\TestCase;

/**
 * The boot check reached through Artisan, with Symfony's command events
 * forwarded as they are outside tests.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ConfigurationBindings::class)]
final class WorkerBootCheckTest extends TestCase
{
    use WithConsoleEvents;

    /**
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->container()->make(Repository::class)->set('mfa.totp.window', 9);
    }

    /**
     * @return void
     */
    public function testAWorkerCommandIsRefusedBeforeItRuns(): void
    {
        $ran = false;

        $this->container()->make(Schedule::class)->call(static function () use (&$ran): void {
            $ran = true;
        })->everyMinute();

        $this->assertThrows(
            fn () => $this->container()->make(Kernel::class)->call('schedule:run'),
            InvalidConfigurationException::class,
            '[totp] mfa.totp.window must be an integer from 0 to 3.',
        );

        self::assertFalse($ran);
    }

    /**
     * @return void
     */
    public function testAnAbbreviatedWorkerCommandIsRefused(): void
    {
        $this->expectException(InvalidConfigurationException::class);

        // Testbench's console kernel rethrows what it would report.
        $this->container()->make(Kernel::class)->handle(new ArrayInput(['command' => 'schedule:ru']), new NullOutput);
    }

    /**
     * @return void
     */
    public function testOtherCommandsStillRun(): void
    {
        $kernel = $this->container()->make(Kernel::class);

        self::assertSame(0, $kernel->call('schedule:list'));
        self::assertSame(1, $kernel->call('mfa:check'));
        self::assertStringContainsString('[totp] mfa.totp.window must be an integer from 0 to 3.', $kernel->output());
    }
}
