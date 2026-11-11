<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Attempts;

use Carbon\CarbonImmutable;
use Illuminate\Database\Connection;
use Illuminate\Database\Grammar;
use Illuminate\Database\Query\Builder;
use Illuminate\Support\Facades\DB;
use SineMacula\Laravel\Mfa\Database\BoundedDelete;
use SineMacula\Laravel\Mfa\Database\GrammarExpression;
use SineMacula\Laravel\Mfa\Database\StorageConnection;
use SineMacula\Laravel\Mfa\Database\TableNames;
use SineMacula\Laravel\Mfa\Database\WriteConnection;
use SineMacula\Laravel\Mfa\Enums\AttemptScope;

/**
 * Throttle window statements on the storage write connection. Each count change
 * is one atomic statement, so concurrent servers never lose an update. A row
 * whose window has ended counts nothing and may be pruned.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class AttemptStore
{
    /**
     * Returns the stored window end the slot came from, or the Unix time a full
     * window ends. A live window with another end (changed config or clock
     * skew) is kept, so earlier attempts are not forgiven.
     *
     * @param  string  $key
     * @param  \SineMacula\Laravel\Mfa\Enums\AttemptScope  $scope
     * @param  int  $max
     * @param  int  $now
     * @param  int  $end
     * @return int|string
     *
     * @throws \InvalidArgumentException
     */
    public function take(string $key, AttemptScope $scope, int $max, int $now, int $end): int|string
    {
        if ($this->writeCount($key, $now, $end, $max) || $this->storeNewRow($key, $scope, $end) || $this->writeCount($key, $now, $end, $max)) {
            return $this->format($end);
        }

        return $this->takeFromStoredWindow($key, $max, $now);
    }

    /**
     * Count one failure regardless of the limit. A single upsert, because on
     * MySQL an update that finds no row takes a gap lock that can deadlock two
     * first failures. Inlined times are safe as the store formats them.
     *
     * @param  string  $key
     * @param  \SineMacula\Laravel\Mfa\Enums\AttemptScope  $scope
     * @param  int  $now
     * @param  int  $end
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public function record(string $key, AttemptScope $scope, int $now, int $end): void
    {
        $table  = TableNames::of(TableNames::ATTEMPTS);
        $nowAt  = $this->format($now);
        $endAt  = $this->format($end);
        $window = static fn (Grammar $grammar): string => $grammar->wrap($table . '.window_ends_at');
        $ended  = static fn (Grammar $grammar): string => $window($grammar) . ' <= ' . $grammar->quoteString($nowAt);
        $hits   = static fn (Grammar $grammar): string => "case when {$ended($grammar)} then 1 else {$grammar->wrap($table . '.hits')} + 1 end";
        $ends   = static fn (Grammar $grammar): string => "case when {$ended($grammar)} then {$grammar->quoteString($endAt)} else {$window($grammar)} end";

        $this->table()->upsert([[
            'key'            => $key,
            'scope'          => $scope->value,
            'hits'           => 1,
            'window_ends_at' => $endAt,
        ]], ['key'], [
            'hits'           => new GrammarExpression($hits),
            'window_ends_at' => new GrammarExpression($ends),
        ]);
    }

    /**
     * A row that has moved on to a later window is left alone.
     *
     * @param  string  $key
     * @param  string  $window
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public function giveBack(string $key, string $window): void
    {
        $this->table()
            ->where('key', $key)
            ->where('window_ends_at', $window)
            ->where('hits', '>', 0)
            ->decrement('hits');
    }

    /**
     * @param  string  $key
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public function forget(string $key): void
    {
        $this->table()->where('key', $key)->delete();
    }

    /**
     * Delete ended windows; a row a concurrent attempt just restarted stays.
     *
     * @param  int  $now
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function prune(int $now): int
    {
        return BoundedDelete::run($this->table()->where('window_ends_at', '<=', $this->format($now)));
    }

    /**
     * @param  list<string>  $keys
     * @return array<string, array{hits: int, ends: int}>
     *
     * @throws \InvalidArgumentException
     */
    public function read(array $keys): array
    {
        $rows = [];

        foreach (WriteConnection::query($this->table())->whereIn('key', $keys)->get(['key', 'hits', 'window_ends_at']) as $row) {

            if (!is_string($row->key)) {
                continue;
            }

            $rows[$row->key] = ['hits' => self::integer($row->hits), 'ends' => self::timestamp($row->window_ends_at)];
        }

        return $rows;
    }

    /**
     * Take from a live stored window with a different end. Returns that window,
     * or the Unix time to retry, at least a second from now.
     *
     * @param  string  $key
     * @param  int  $max
     * @param  int  $now
     * @return int|string
     *
     * @throws \InvalidArgumentException
     */
    private function takeFromStoredWindow(string $key, int $max, int $now): int|string
    {
        $row = $this->read([$key])[$key] ?? null;

        if ($row === null || $row['ends'] <= $now) {
            return $now + 1;
        }

        $window = $this->format($row['ends']);

        if ($row['hits'] < $max && $this->countIn($key, $window, $max)) {
            return $window;
        }

        return $row['ends'];
    }

    /**
     * @param  string  $key
     * @param  string  $window
     * @param  int  $max
     * @return bool
     *
     * @throws \InvalidArgumentException
     *
     * @phpstan-impure
     *
     * @imperative
     */
    private function countIn(string $key, string $window, int $max): bool
    {
        return $this->table()
            ->where('key', $key)
            ->where('window_ends_at', $window)
            ->where('hits', '<', $max)
            ->increment('hits') === 1;
    }

    /**
     * Hits are assigned before the window because MySQL evaluates UPDATE
     * assignments left to right.
     *
     * @param  string  $key
     * @param  int  $now
     * @param  int  $end
     * @param  int  $max
     * @return bool
     *
     * @throws \InvalidArgumentException
     *
     * @phpstan-impure
     */
    private function writeCount(string $key, int $now, int $end, int $max): bool
    {
        $connection = $this->connection();
        $grammar    = $connection->getQueryGrammar();
        $table      = $grammar->wrapTable(TableNames::of(TableNames::ATTEMPTS));
        $hits       = $grammar->wrap('hits');
        $window     = $grammar->wrap('window_ends_at');
        $nowAt      = $this->format($now);

        $sql = "update {$table} set {$hits} = case when {$window} <= ? then 1 else {$hits} + 1 end,"
            . " {$window} = case when {$window} <= ? then ? else {$window} end where {$grammar->wrap('key')} = ?"
            . " and ({$window} <= ? or ({$window} = ? and {$hits} < ?))";

        return $connection->update($sql, [$nowAt, $nowAt, $this->format($end), $key, $nowAt, $this->format($end), $max]) === 1;
    }

    /**
     * @param  string  $key
     * @param  \SineMacula\Laravel\Mfa\Enums\AttemptScope  $scope
     * @param  int  $end
     * @return bool
     *
     * @throws \InvalidArgumentException
     *
     * @phpstan-impure
     */
    private function storeNewRow(string $key, AttemptScope $scope, int $end): bool
    {
        return $this->table()->insertOrIgnore([
            'key'            => $key,
            'scope'          => $scope->value,
            'hits'           => 1,
            'window_ends_at' => $this->format($end),
        ]) === 1;
    }

    /**
     * @return \Illuminate\Database\Query\Builder
     *
     * @throws \InvalidArgumentException
     */
    private function table(): Builder
    {
        return $this->connection()->table(TableNames::of(TableNames::ATTEMPTS));
    }

    /**
     * @return \Illuminate\Database\Connection
     *
     * @throws \InvalidArgumentException
     */
    private function connection(): Connection
    {
        return DB::connection(StorageConnection::name());
    }

    /**
     * In the application's timezone.
     *
     * @param  int  $timestamp
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    private function format(int $timestamp): string
    {
        return CarbonImmutable::createFromTimestamp($timestamp, date_default_timezone_get())
            ->format($this->connection()->getQueryGrammar()->getDateFormat());
    }

    /**
     * @param  mixed  $value
     * @return int
     */
    private static function integer(mixed $value): int
    {
        return is_numeric($value) ? (int) $value : 0;
    }

    /**
     * Anything that is not a time reads as the epoch, so it counts as ended.
     *
     * @param  mixed  $value
     * @return int
     */
    private static function timestamp(mixed $value): int
    {
        return is_string($value) && $value !== '' ? CarbonImmutable::parse($value, date_default_timezone_get())->getTimestamp() : 0;
    }
}
