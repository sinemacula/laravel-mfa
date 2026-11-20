<?php

declare(strict_types = 1);

namespace Tests\Unit\Concerns;

use Carbon\Carbon;
use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Date;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Mfa\Concerns\StoresTimesInUtc;
use SineMacula\Laravel\Mfa\Models\IdentityState;
use Tests\TestCase;

/**
 * Run in Europe/London, where the clocks go back at 01:00 UTC on 25 October
 * 2026.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversTrait(StoresTimesInUtc::class)]
final class StoresTimesInUtcTest extends TestCase
{
    /**
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->useTimezone('Europe/London');
    }

    /**
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Carbon::setTestNow();
        Date::useDefault();

        parent::tearDown();
    }

    /**
     * @return void
     */
    public function testALocalTimeIsStoredInUtc(): void
    {
        $state = new IdentityState;

        $state->locked_until = CarbonImmutable::parse('2026-10-25 00:30:00', 'UTC')->setTimezone('Europe/London');

        self::assertSame('2026-10-25 00:30:00', $state->getAttributes()['locked_until']);
    }

    /**
     * Either side of the clocks going back, where the wall-clock time repeats.
     *
     * @return void
     */
    public function testAStoredTimeReadsAsUtc(): void
    {
        $state = new IdentityState;

        foreach (['2026-10-25 00:30:00', '2026-10-25 01:30:00'] as $stored) {

            $state->setRawAttributes(['locked_until' => $stored]);

            self::assertSame(CarbonImmutable::parse($stored, 'UTC')->getTimestamp(), $state->locked_until?->getTimestamp());
            self::assertSame('UTC', $state->locked_until->getTimezone()->getName());
        }
    }

    /**
     * @return void
     */
    public function testAStringWithAnOffsetKeepsItsInstant(): void
    {
        $state = new IdentityState;

        $state->setAttribute('locked_until', '2026-10-25T01:30:00+01:00');

        self::assertSame('2026-10-25 00:30:00', $state->getAttributes()['locked_until']);
    }

    /**
     * A day before the month, which a generic parse would misread, read through
     * the configured date class.
     *
     * @return void
     */
    public function testAModelsOwnDateFormatReadsAsUtc(): void
    {
        $model = new class extends Model {
            use StoresTimesInUtc;

            /** @var ?string The format the columns hold. */
            protected $dateFormat = 'd/m/Y H:i:s';

            /**
             * @return array<string, string>
             */
            #[\Override]
            protected function casts(): array
            {
                return ['at' => 'datetime'];
            }
        };

        Date::use(CarbonImmutable::class);

        $model->setRawAttributes(['at' => '12/10/2026 01:30:00']);

        $at = $model->getAttribute('at');

        self::assertInstanceOf(CarbonImmutable::class, $at);
        self::assertSame(CarbonImmutable::parse('2026-10-12 01:30:00', 'UTC')->getTimestamp(), $at->getTimestamp());
    }

    /**
     * @return void
     */
    public function testAUnixTimeIsStoredInUtc(): void
    {
        $state   = new IdentityState;
        $instant = CarbonImmutable::parse('2026-10-25 01:30:00', 'UTC');

        $state->setAttribute('locked_until', (string) $instant->getTimestamp());

        self::assertSame('2026-10-25 01:30:00', $state->getAttributes()['locked_until']);
    }

    /**
     * @return void
     */
    public function testTimestampsAreStoredInUtc(): void
    {
        Carbon::setTestNow(Carbon::parse('2026-07-01 12:00:00', 'UTC'));

        $state = IdentityState::query()->create(['authenticatable_type' => 'users', 'authenticatable_id' => '42']);

        self::assertSame('2026-07-01 12:00:00', $state->getAttributes()['created_at']);

        Carbon::setTestNow(Carbon::parse('2026-07-01 13:00:00', 'UTC'));

        $state->touch();

        self::assertSame('2026-07-01 13:00:00', $state->getAttributes()['updated_at']);
    }
}
