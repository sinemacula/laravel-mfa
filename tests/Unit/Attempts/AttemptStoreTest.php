<?php

declare(strict_types = 1);

namespace Tests\Unit\Attempts;

use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Attempts\AttemptStore;
use SineMacula\Laravel\Mfa\Enums\AttemptScope;
use Tests\TestCase;

/**
 * Tests for `AttemptStore`: slots taken from a window up to its limit and given
 * back to it, failures recorded past it, windows that restart once ended, and
 * rows held, read and forgotten.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AttemptStore::class)]
final class AttemptStoreTest extends TestCase
{
    /** @var string The key of the row under test. */
    private const string KEY = 'row-key';

    /** @var int The Unix time the tests run at. */
    private const int NOW = 1793534400;

    /**
     * The first slot creates the row with one attempt, in the window that ends
     * at the given end, as stored.
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
     * Slots are taken up to the limit; past it the window's end is answered and
     * nothing is counted, so a refused attempt does not extend the window.
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
     * Once its window has ended, a row starts a new window with the attempt.
     *
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
     * A live window that ends elsewhere than computed, as after a change of the
     * window's length, is counted in as stored, up to the limit.
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
     * A slot given back frees room in the window it came from, and never takes
     * the count below nothing or touches a later window.
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
     * A recorded failure counts however many the window already holds, and
     * starts a window when there is none.
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
     * A held row takes the given count and end whatever it held, and a
     * forgotten row is gone.
     *
     * @return void
     */
    public function testARowIsHeldAndForgotten(): void
    {
        $store = $this->store();

        $store->hold(self::KEY, AttemptScope::FACTOR, 5, self::NOW + 900);

        self::assertSame(['hits' => 5, 'ends' => self::NOW + 900], $store->read([self::KEY])[self::KEY]);
        self::assertSame('factor', DB::table('mfa_attempts')->where('key', self::KEY)->value('scope'));

        $store->hold(self::KEY, AttemptScope::FACTOR, 6, self::NOW + 1800);

        self::assertSame(['hits' => 6, 'ends' => self::NOW + 1800], $store->read([self::KEY])[self::KEY]);

        $store->forget(self::KEY);

        self::assertSame([], $store->read([self::KEY]));
    }

    /**
     * Only the rows asked for are read, every one of them, and a missing one is
     * left out.
     *
     * @return void
     */
    public function testOnlyTheRowsAskedForAreRead(): void
    {
        $store = $this->store();

        $store->hold('first', AttemptScope::FACTOR, 1, self::NOW + 60);
        $store->hold('second', AttemptScope::FACTOR, 2, self::NOW + 120);
        $store->hold('third', AttemptScope::FACTOR, 3, self::NOW + 180);

        $rows = $store->read(['second', 'missing', 'third']);

        ksort($rows);

        self::assertSame([
            'second' => ['hits' => 2, 'ends' => self::NOW + 120],
            'third'  => ['hits' => 3, 'ends' => self::NOW + 180],
        ], $rows);
    }

    /**
     * Resolve the store.
     *
     * @return \SineMacula\Laravel\Mfa\Attempts\AttemptStore
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function store(): AttemptStore
    {
        return $this->container()->make(AttemptStore::class);
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
