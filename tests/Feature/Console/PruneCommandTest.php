<?php

declare(strict_types = 1);

namespace Tests\Feature\Console;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Console\Kernel;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
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
     * It deletes without the manager, so it checks the configuration itself
     * before deleting anything.
     *
     * @return void
     */
    public function testAnInvalidConfigurationStopsIt(): void
    {
        $expired = CarbonImmutable::now()->subDays(31);

        $this->insertCodes(1, $expired);

        DB::table('mfa_enrollments')->insert([
            'id'                   => (string) Str::ulid(),
            'factor_id'            => (string) Str::ulid(),
            'authenticatable_type' => 'user',
            'authenticatable_id'   => '1',
            'grant_hash'           => str_repeat('a', 64),
            'application'          => 'web',
            'session_id'           => 'session',
            'generation'           => 1,
            'authority'            => 'step_up',
            'expires_at'           => $expired,
        ]);

        $this->container()->make(Repository::class)->set('mfa.totp.window', 9);

        $this->assertThrows(fn () => $this->container()->make(Kernel::class)->call('mfa:prune'), InvalidConfigurationException::class);

        self::assertSame(1, DB::table('mfa_codes')->count());
        self::assertSame(1, DB::table('mfa_enrollments')->count());
    }

    /**
     * @return void
     */
    public function testEveryOldRowGoesInMoreThanOneBatch(): void
    {
        $old = CarbonImmutable::now()->subDays(31);
        $new = CarbonImmutable::now()->subDays(29);

        $this->insertCodes(2001, $old);
        $this->insertCodes(1, $new);
        $this->insertRecoveryCodes(2001, $old);
        $this->insertRecoveryCodes(1, $new);

        self::assertSame(0, $this->container()->make(Kernel::class)->call('mfa:prune'));

        $output = Artisan::output();

        self::assertStringContainsString('Delivered codes: 2001', $output);
        self::assertStringContainsString('Recovery codes: 2001', $output);
        self::assertSame(1, DB::table('mfa_codes')->count());
        self::assertSame(1, DB::table('mfa_recovery_codes')->count());
    }

    /**
     * @param  int  $count
     * @param  \Carbon\CarbonImmutable  $expiresAt
     * @return void
     */
    private function insertCodes(int $count, CarbonImmutable $expiresAt): void
    {
        $rows = array_map(static fn (): array => [
            'id'                   => (string) Str::ulid(),
            'factor_id'            => 'factor',
            'authenticatable_type' => 'user',
            'authenticatable_id'   => '1',
            'purpose'              => 'sign_in',
            'application'          => 'web',
            'destination_hash'     => str_repeat('d', 64),
            'code_hash'            => str_repeat('c', 64),
            'sent_at'              => $expiresAt->subMinutes(10),
            'sent_times'           => '[]',
            'expires_at'           => $expiresAt,
        ], range(1, $count));

        foreach (array_chunk($rows, 500) as $chunk) {
            DB::table('mfa_codes')->insert($chunk);
        }
    }

    /**
     * @param  int  $count
     * @param  \Carbon\CarbonImmutable  $usedAt
     * @return void
     */
    private function insertRecoveryCodes(int $count, CarbonImmutable $usedAt): void
    {
        $rows = array_map(static fn (): array => [
            'id'                   => (string) Str::ulid(),
            'authenticatable_type' => 'user',
            'authenticatable_id'   => '1',
            'code_hash'            => 'hash',
            'generation'           => 1,
            'used_at'              => $usedAt,
        ], range(1, $count));

        foreach (array_chunk($rows, 500) as $chunk) {
            DB::table('mfa_recovery_codes')->insert($chunk);
        }
    }
}
