<?php

declare(strict_types = 1);

namespace Tests\Integration\Database;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Mfa\Concerns\ActsAsFactor;
use SineMacula\Laravel\Mfa\Drivers\TotpDriver;
use SineMacula\Laravel\Mfa\Drivers\TotpSettings;
use SineMacula\Laravel\Mfa\Models\Factor;
use Tests\Fixtures\Drivers\AuthenticatorApp;
use Tests\TestCase;

/**
 * Two requests racing with codes for one TOTP factor: only one records the
 * step, whichever database holds the factors.
 *
 * The second request runs on a connection of its own (`racer`) to the same
 * database, and opens its transaction and reads the factor before the first
 * request verifies, so its copy shows no step accepted, and on MySQL its reads
 * come from a snapshot taken before the first request committed. The first
 * request then verifies and commits on the default connection, and the second
 * verifies with the same code, or one for an earlier step. The step is checked
 * by the database as it records it, against the row as committed, so the
 * second request is refused although everything it read says otherwise. On
 * SQLite, whose in-memory test database one connection holds, both requests
 * share that connection, and the first records its step inside the second's
 * transaction.
 *
 * The tables are committed rather than wrapped in a transaction of the test's
 * own, so the second connection sees what the first commits; the migrations
 * roll them back after each test.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(TotpDriver::class)]
#[CoversTrait(ActsAsFactor::class)]
final class TotpReplayRaceTest extends TestCase
{
    /** @var int The frozen time: 15 seconds into time step 60000000. */
    private const int NOW = 1800000015;

    /** @var int The time step the frozen time falls in. */
    private const int STEP = 60000000;

    /** @var string The connection the second request runs on. */
    private string $racer = 'testing';

    /**
     * Freeze time in the middle of a step.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->travelTo(CarbonImmutable::createFromTimestamp(self::NOW));
    }

    /**
     * Of two requests with the same code, only the one that records the step
     * first passes.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testOnlyOneOfTwoRequestsWithTheSameCodePasses(): void
    {
        $factor = $this->storedFactor();

        [$first, $second] = $this->race($factor, static fn (Factor $copy): string => AuthenticatorApp::code($copy));

        self::assertTrue($first);
        self::assertFalse($second);
        self::assertSame(self::STEP, $this->storedStep($factor));
    }

    /**
     * Once one request records a step, a request with a code for an earlier
     * step of the window is refused, though its copy shows no step accepted.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARequestWithAnEarlierStepLosesToALaterOne(): void
    {
        $factor = $this->storedFactor();

        $later   = static fn (Factor $copy): string => AuthenticatorApp::code($copy, 1);
        $current = static fn (Factor $copy): string => AuthenticatorApp::code($copy);

        [$first, $second] = $this->race($factor, $later, $current);

        self::assertTrue($first);
        self::assertFalse($second);
        self::assertSame(self::STEP + 1, $this->storedStep($factor));
    }

    /**
     * Give the second request a connection of its own to the test database,
     * unless the database is SQLite in memory, which only one connection
     * holds.
     *
     * @param  mixed  $app
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        assert($app instanceof Application);

        /** @var \Illuminate\Config\Repository $config */
        $config = $app->make(Repository::class);

        $testing = $config->get('database.connections.testing');

        if (!is_array($testing) || ($testing['driver'] ?? null) === 'sqlite') {
            return;
        }

        $config->set('database.connections.racer', $testing);

        $this->racer = 'racer';
    }

    /**
     * Run the race: the second request opens its transaction and reads the
     * factor, the first verifies its code and commits, then the second
     * verifies its own and commits. Returns whether each passed.
     *
     * @param  \SineMacula\Laravel\Mfa\Models\Factor  $factor
     * @param  \Closure(\SineMacula\Laravel\Mfa\Models\Factor): string  $firstCode
     * @param  ?\Closure(\SineMacula\Laravel\Mfa\Models\Factor): string  $secondCode
     * @return array{0: bool, 1: bool}
     *
     * @throws \Throwable
     */
    private function race(Factor $factor, \Closure $firstCode, ?\Closure $secondCode = null): array
    {
        $driver = new TotpDriver(new TotpSettings($this->container()->make(Repository::class)));
        $racer  = DB::connection($this->racer);

        $racer->beginTransaction();

        try {
            $second = Factor::on($this->racer)->findOrFail($factor->id);

            self::assertNull($second->getLastAcceptedStep());

            $first = Factor::query()->findOrFail($factor->id);

            $firstPassed  = $driver->verify($first, $firstCode($first));
            $secondPassed = $driver->verify($second, ($secondCode ?? $firstCode)($second));

            $racer->commit();
        } catch (\Throwable $exception) {
            $racer->rollBack();

            throw $exception;
        }

        return [$firstPassed, $secondPassed];
    }

    /**
     * Store a confirmed TOTP factor with no step accepted.
     *
     * @return \SineMacula\Laravel\Mfa\Models\Factor
     */
    private function storedFactor(): Factor
    {
        return Factor::query()->create([
            ...AuthenticatorApp::FACTOR,
            'authenticatable_type' => 'user',
            'authenticatable_id'   => '1',
            'status'               => 'confirmed',
        ]);
    }

    /**
     * The step stored in the factor's row, as committed.
     *
     * @param  \SineMacula\Laravel\Mfa\Models\Factor  $factor
     * @return ?int
     */
    private function storedStep(Factor $factor): ?int
    {
        $step = DB::table('mfa_factors')->where('id', $factor->id)->value('last_accepted_step');

        return $step === null ? null : (int) $step;
    }
}
