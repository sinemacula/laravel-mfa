<?php

declare(strict_types = 1);

namespace Tests\Unit\Attempts;

use Carbon\CarbonImmutable;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Attempts\AttemptSettings;
use SineMacula\Laravel\Mfa\Attempts\AttemptStore;
use SineMacula\Laravel\Mfa\Enums\AttemptScope;
use Tests\TestCase;

/**
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AttemptStore::class)]
final class AttemptStoreTest extends TestCase
{
    /** @var string A row key, as long as the digests the store is keyed by. */
    private const string KEY = '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08';

    /** @var int The Unix time the tests run at. */
    private const int NOW = 1793534400;

    /**
     * With one attempt, in a window ending at the given end.
     *
     * @return void
     */
    public function testTheFirstSlotCreatesTheRow(): void
    {
        $window = $this->store()->take(self::KEY, AttemptScope::IP, 2, self::NOW, self::NOW + 60);

        self::assertSame($this->formatted(self::NOW + 60), $window);
        self::assertSame([self::KEY => ['hits' => 1, 'ends' => self::NOW + 60]], $this->store()->read([self::KEY]));
        self::assertSame('ip', DB::table('mfa_attempts')->where('key', self::KEY)->value('scope'));
    }

    /**
     * So an insert that ignores its conflict has no value a database could
     * coerce into another row's.
     *
     * @return void
     */
    public function testANewRowsWindowIsBoundedByTheSettings(): void
    {
        config()->set('mfa.attempts.window_seconds', 86400);

        $settings = $this->container()->make(AttemptSettings::class);
        $end      = self::NOW + $settings->windowSeconds();

        self::assertSame(self::NOW + 86400, $end);

        $this->store()->take(self::KEY, AttemptScope::IP, 2, self::NOW, $end);

        self::assertSame($end, $this->store()->read([self::KEY])[self::KEY]['ends']);
    }

    /**
     * Past the limit nothing is counted, so a refused attempt does not extend
     * the window.
     *
     * @return void
     */
    public function testAFullWindowAnswersItsEndAndCountsNothing(): void
    {
        $store = $this->store();

        $store->take(self::KEY, AttemptScope::IP, 2, self::NOW, self::NOW + 60);

        self::assertSame($this->formatted(self::NOW + 60), $store->take(self::KEY, AttemptScope::IP, 2, self::NOW + 1, self::NOW + 61));
        self::assertSame(self::NOW + 60, $store->take(self::KEY, AttemptScope::IP, 2, self::NOW + 2, self::NOW + 62));
        self::assertSame(self::NOW + 60, $store->take(self::KEY, AttemptScope::IP, 2, self::NOW + 3, self::NOW + 63));
        self::assertSame(['hits' => 2, 'ends' => self::NOW + 60], $store->read([self::KEY])[self::KEY]);
    }

    /**
     * @return void
     */
    public function testAnEndedWindowRestarts(): void
    {
        $store = $this->store();

        $store->take(self::KEY, AttemptScope::IP, 1, self::NOW, self::NOW + 60);

        self::assertSame($this->formatted(self::NOW + 120), $store->take(self::KEY, AttemptScope::IP, 1, self::NOW + 60, self::NOW + 120));
        self::assertSame(['hits' => 1, 'ends' => self::NOW + 120], $store->read([self::KEY])[self::KEY]);
    }

    /**
     * As after a change of the window's length; counted in as stored, up to the
     * limit.
     *
     * @return void
     */
    public function testALiveWindowEndingElsewhereIsCountedIn(): void
    {
        $store = $this->store();

        $store->take(self::KEY, AttemptScope::IP, 2, self::NOW, self::NOW + 60);

        self::assertSame($this->formatted(self::NOW + 60), $store->take(self::KEY, AttemptScope::IP, 2, self::NOW + 1, self::NOW + 301));
        self::assertSame(self::NOW + 60, $store->take(self::KEY, AttemptScope::IP, 2, self::NOW + 2, self::NOW + 302));
        self::assertSame(['hits' => 2, 'ends' => self::NOW + 60], $store->read([self::KEY])[self::KEY]);
    }

    /**
     * It never takes the count below nothing or touches a later window.
     *
     * @return void
     */
    public function testASlotGivenBackFreesRoomInItsOwnWindow(): void
    {
        $store  = $this->store();
        $window = $store->take(self::KEY, AttemptScope::IP, 1, self::NOW, self::NOW + 60);

        self::assertIsString($window);

        $store->giveBack(self::KEY, $window);
        $store->giveBack(self::KEY, $window);

        self::assertSame(0, $store->read([self::KEY])[self::KEY]['hits']);

        $store->take(self::KEY, AttemptScope::IP, 1, self::NOW + 60, self::NOW + 120);
        $store->giveBack(self::KEY, $window);

        self::assertSame(['hits' => 1, 'ends' => self::NOW + 120], $store->read([self::KEY])[self::KEY]);
    }

    /**
     * It starts a window when there is none.
     *
     * @return void
     */
    public function testARecordedFailureCountsPastAnyLimit(): void
    {
        $store = $this->store();

        $store->record(self::KEY, AttemptScope::IDENTITY, self::NOW, self::NOW + 60);
        $store->record(self::KEY, AttemptScope::IDENTITY, self::NOW + 1, self::NOW + 61);
        $store->record(self::KEY, AttemptScope::IDENTITY, self::NOW + 2, self::NOW + 62);

        self::assertSame(['hits' => 3, 'ends' => self::NOW + 60], $store->read([self::KEY])[self::KEY]);
        self::assertSame('identity', DB::table('mfa_attempts')->where('key', self::KEY)->value('scope'));

        $store->record(self::KEY, AttemptScope::IDENTITY, self::NOW + 60, self::NOW + 120);

        self::assertSame(['hits' => 1, 'ends' => self::NOW + 120], $store->read([self::KEY])[self::KEY]);
    }

    /**
     * The other rows stay.
     *
     * @return void
     */
    public function testARowIsForgotten(): void
    {
        $store = $this->store();

        $this->storeRow(self::KEY, 5, self::NOW + 900);
        $this->storeRow($this->key('other'), 1, self::NOW + 900);

        self::assertSame(['hits' => 5, 'ends' => self::NOW + 900], $store->read([self::KEY])[self::KEY]);

        $store->forget(self::KEY);

        self::assertSame([], $store->read([self::KEY]));
        self::assertCount(1, $store->read([$this->key('other')]));
    }

    /**
     * A missing one is left out.
     *
     * @return void
     */
    public function testOnlyTheRowsAskedForAreRead(): void
    {
        $this->storeRow($this->key('first'), 1, self::NOW + 60);
        $this->storeRow($this->key('second'), 2, self::NOW + 120);
        $this->storeRow($this->key('third'), 3, self::NOW + 180);

        $rows = $this->store()->read([$this->key('second'), $this->key('missing'), $this->key('third')]);

        self::assertCount(2, $rows);
        self::assertSame(['hits' => 2, 'ends' => self::NOW + 120], $rows[$this->key('second')]);
        self::assertSame(['hits' => 3, 'ends' => self::NOW + 180], $rows[$this->key('third')]);
    }

    /**
     * When a concurrent request ends a full window first, the slot is refused,
     * to be sought again the next second.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAWindowEndingWhileASlotIsSoughtIsSoughtAgainNextSecond(): void
    {
        $store = $this->store();

        $store->take(self::KEY, AttemptScope::IP, 1, self::NOW, self::NOW + 60);

        $statements = 0;

        Event::listen(QueryExecuted::class, function () use (&$statements): void {
            if (++$statements !== 3) {
                return;
            }

            DB::table('mfa_attempts')->where('key', self::KEY)->update(['hits' => 0, 'window_ends_at' => $this->formatted(self::NOW + 1)]);
        });

        self::assertSame(self::NOW + 2, $store->take(self::KEY, AttemptScope::IP, 1, self::NOW + 1, self::NOW + 61));
        self::assertSame(['hits' => 0, 'ends' => self::NOW + 1], $store->read([self::KEY])[self::KEY]);
    }

    /**
     * @param  string  $key
     * @param  int  $hits
     * @param  int  $ends
     * @return void
     */
    private function storeRow(string $key, int $hits, int $ends): void
    {
        DB::table('mfa_attempts')->insert([
            'key'            => $key,
            'scope'          => AttemptScope::IP->value,
            'hits'           => $hits,
            'window_ends_at' => CarbonImmutable::createFromTimestamp($ends, date_default_timezone_get())->format('Y-m-d H:i:s'),
        ]);
    }

    /**
     * @return \SineMacula\Laravel\Mfa\Attempts\AttemptStore
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function store(): AttemptStore
    {
        return $this->container()->make(AttemptStore::class);
    }

    /**
     * As long as the digests: the key column has a fixed width, which some
     * databases pad a shorter key to.
     *
     * @param  string  $name
     * @return string
     */
    private function key(string $name): string
    {
        return hash('sha256', $name);
    }

    /**
     * A Unix time as the storage connection stores it.
     *
     * @param  int  $timestamp
     * @return string
     */
    private function formatted(int $timestamp): string
    {
        return CarbonImmutable::createFromTimestamp($timestamp, date_default_timezone_get())->format(DB::connection()->getQueryGrammar()->getDateFormat());
    }
}
