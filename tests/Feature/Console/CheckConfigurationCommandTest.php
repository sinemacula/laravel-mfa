<?php

declare(strict_types = 1);

namespace Tests\Feature\Console;

use Illuminate\Config\Repository;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Illuminate\Testing\PendingCommand;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Console\CheckConfigurationCommand;
use SineMacula\Laravel\Mfa\Contracts\FirstFactorResolver;
use Tests\TestCase;

/**
 * Feature tests for `mfa:check`: it lists every subject without a problem as OK
 * and every problem with its subject, exits `1` when there is one and `0` when
 * there is none, and opens no database connection.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CheckConfigurationCommand::class)]
final class CheckConfigurationCommandTest extends TestCase
{
    /** @var list<string> The package-wide subjects, in the order they are reported. */
    private const array SUBJECTS = ['storage', 'factor', 'identity_state', 'totp', 'codes', 'recovery_codes', 'attempts', 'enrollment', 'proofs', 'lifecycle', 'applications'];

    /**
     * The command is registered under its name.
     *
     * @return void
     */
    public function testTheCommandIsRegistered(): void
    {
        self::assertInstanceOf(CheckConfigurationCommand::class, Artisan::all()['mfa:check'] ?? null);
    }

    /**
     * The shipped configuration passes, each subject reported as OK, without a
     * database query.
     *
     * @return void
     */
    public function testTheShippedConfigurationPasses(): void
    {
        $queries = 0;

        DB::listen(static function () use (&$queries): void {
            $queries++;
        });

        $command = $this->artisan('mfa:check');

        self::assertInstanceOf(PendingCommand::class, $command);

        foreach (self::SUBJECTS as $subject) {
            $command->expectsOutput("[{$subject}] OK");
        }

        $command->assertExitCode(0)->run();

        self::assertSame(0, $queries);
    }

    /**
     * Each problem is listed with its subject, every other subject is OK, and
     * the command fails.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testEachProblemIsListedAndTheCommandFails(): void
    {
        $config = $this->container()->make(Repository::class);

        $config->set('mfa.codes.length', 4);
        $config->set('mfa.attempts.factor_limit', 0);
        $config->set('mfa.applications', ['web' => ['types' => ['totp']]]);

        $problems = [
            'codes'            => '[codes] mfa.codes.length must be an integer from 6 to 10.',
            'attempts'         => '[attempts] mfa.attempts.factor_limit must be an integer from 1 to 20.',
            'applications.web' => '[applications.web] The application declares no first_factor, and no ' . FirstFactorResolver::class . ' is bound to report it.',
        ];

        $command = $this->artisan('mfa:check');

        self::assertInstanceOf(PendingCommand::class, $command);

        foreach ([...self::SUBJECTS, 'applications.web'] as $subject) {
            $command->expectsOutput($problems[$subject] ?? "[{$subject}] OK");
        }

        $command->doesntExpectOutput('[codes] OK')
            ->doesntExpectOutput('[applications.web] OK')
            ->assertExitCode(1)
            ->run();
    }

    /**
     * A configured application without a problem is reported as OK.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAConfiguredApplicationWithoutAProblemIsOk(): void
    {
        $this->container()->make(Repository::class)->set('mfa.applications', ['web' => [
            'types'        => ['totp'],
            'first_factor' => ['method' => 'password', 'channel' => 'password'],
        ]]);

        $command = $this->artisan('mfa:check');

        self::assertInstanceOf(PendingCommand::class, $command);

        $command->expectsOutput('[applications.web] OK')
            ->assertExitCode(0)
            ->run();
    }
}
