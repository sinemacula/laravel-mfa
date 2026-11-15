<?php

declare(strict_types = 1);

namespace Tests\Feature\Console;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Console\Kernel;
use Illuminate\Support\Facades\Artisan;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Console\PruneCommand;
use SineMacula\Laravel\Mfa\Exceptions\InvalidConfigurationException;
use Tests\TestCase;

/**
 * Tests for `PruneCommand`; what it prunes is in `PruningTest`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PruneCommand::class)]
final class PruneCommandTest extends TestCase
{
    /**
     * @return void
     */
    public function testItSaysWhatItDeletes(): void
    {
        $command = Artisan::all()['mfa:prune'] ?? null;

        self::assertInstanceOf(PruneCommand::class, $command);
        self::assertSame('Delete expired enrolments, expired codes, used or replaced recovery codes and ended throttle windows', $command->getDescription());
    }

    /**
     * @return void
     */
    public function testWithNothingToPruneItPrintsZeroCounts(): void
    {
        self::assertSame(0, $this->container()->make(Kernel::class)->call('mfa:prune'));

        $output = Artisan::output();

        foreach (['Enrolments: 0', 'Delivered codes: 0', 'Recovery codes: 0', 'Throttle rows: 0'] as $line) {
            self::assertStringContainsString($line, $output);
        }
    }

    /**
     * It deletes without the manager, so it checks the configuration itself.
     *
     * @return void
     */
    public function testAnInvalidConfigurationStopsIt(): void
    {
        $this->container()->make(Repository::class)->set('mfa.totp.window', 9);

        $this->expectException(InvalidConfigurationException::class);

        $this->container()->make(Kernel::class)->call('mfa:prune');
    }
}
