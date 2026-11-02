<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Attempts;

use Carbon\CarbonImmutable;
use Illuminate\Database\Connection;
use Illuminate\Database\Query\Builder;
use Illuminate\Database\Query\Expression;
use Illuminate\Support\Facades\DB;
use SineMacula\Laravel\Mfa\Database\BoundedDelete;
use SineMacula\Laravel\Mfa\Database\StorageConnection;
use SineMacula\Laravel\Mfa\Database\TableNames;
use SineMacula\Laravel\Mfa\Database\WriteConnection;
use SineMacula\Laravel\Mfa\Enums\AttemptScope;

/**
 * The statements behind the temporary throttles, on the storage connection and
 * always on its write PDO. Every change to a count is one statement that the
 * database applies atomically, so concurrent attempts on any number of servers
 * can never read a count, add to it, and write it back over each other: a slot
 * taken from a window that has room is the only way an attempt gets through a
 * full one's limit.
 *
 * Each row is keyed by `AttemptKeys`, counts `hits` and ends its window at
 * `window_ends_at`. A row whose window has ended counts nothing, and the next
 * attempt starts a new window with it; a row is never needed once its window
 * has ended, so pruning may delete it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class AttemptStore
{
    /**
     * Take one slot of the row's window, unless the window is full: a row whose
     * window has ended starts the window that ends at `$end` with this attempt,
     * and a missing row is created with it. Returns the end of the window the
     * slot was taken from, as stored; when the window is full, the Unix time it
     * ends instead.
     *
     * A live row whose window does not end at `$end` was started under a
     * different window length, or by a server whose clock is ahead: its own
     * window is kept and counted in, so a change of configuration neither
     * forgives earlier attempts nor loses track of the window a slot came from.
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
     * Count one failure in the row's window, however many it already has: a
     * missing row is created with it, and a row whose window has ended starts
     * the window that ends at `$end` with it.
     *
     * It is one upsert, so it never runs an update that finds no row: inside a
     * transaction on MySQL, such an update holds a gap lock until the commit,
     * and two transactions recording their first failure under different keys
     * in the same gap would then deadlock on each other's insert. The count is
     * assigned before the window, as in `writeCount()`. The times are written
     * into the update as literals, which is safe as the store formats them
     * itself.
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
        $grammar = $this->connection()->getQueryGrammar();
        $table   = TableNames::of(TableNames::ATTEMPTS);
        $hits    = $grammar->wrap($table . '.hits');
        $window  = $grammar->wrap($table . '.window_ends_at');
        $ended   = "{$window} <= " . $grammar->quoteString($this->format($now));

        $this->table()->upsert([[
            'key'            => $key,
            'scope'          => $scope->value,
            'hits'           => 1,
            'window_ends_at' => $this->format($end),
        ]], ['key'], [
            'hits'           => new Expression("case when {$ended} then 1 else {$hits} + 1 end"),
            'window_ends_at' => new Expression("case when {$ended} then " . $grammar->quoteString($this->format($end)) . " else {$window} end"),
        ]);
    }

    /**
     * Store the row with the given count and a window that ends at `$until`,
     * whatever it held before: how a lockout is recorded.
     *
     * @param  string  $key
     * @param  \SineMacula\Laravel\Mfa\Enums\AttemptScope  $scope
     * @param  int  $hits
     * @param  int  $until
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public function hold(string $key, AttemptScope $scope, int $hits, int $until): void
    {
        $this->table()->upsert([[
            'key'            => $key,
            'scope'          => $scope->value,
            'hits'           => $hits,
            'window_ends_at' => $this->format($until),
        ]], ['key'], ['hits', 'window_ends_at']);
    }

    /**
     * Give back one slot taken from the window that ends at `$window`, as
     * `take()` returned it; a row that has moved on to a later window, or holds
     * no attempt, is left alone.
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
     * Delete the row, ending its window at once.
     *
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
     * Delete the rows whose window has ended, and return how many. The end is
     * part of each delete, so a row a concurrent attempt has just started a new
     * window on stays.
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
     * Read the rows, by key, as the number of attempts in their window and the
     * Unix time it ends, from the write PDO.
     *
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
     * Read the row the statements could not take a slot from, and take one from
     * its stored window when that is live, does not end at the computed end,
     * and has room. Returns that window as stored, or the Unix time the attempt
     * may be made again: the stored window's end, and never earlier than a
     * second from now (a row that ended or went in the meantime is worth one
     * more try).
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
     * Add one attempt to the row's stored window, in one statement, while that
     * window is still the one stored and has room. Returns whether it did.
     *
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
     * Add one attempt to an existing row in one statement: the row's window
     * restarts when it has ended, and only a window that ends at `$end` and has
     * room is counted in (any other live window is left untouched). Returns
     * whether the row was changed.
     *
     * The count is assigned before the window: MySQL evaluates the assignments
     * of an UPDATE from left to right, so the count's condition must read the
     * window before it is moved.
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
     * Create the row with this attempt, unless another request created it
     * first. Returns whether this call created it.
     *
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
     * A query on the attempts table, on the storage connection.
     *
     * @return \Illuminate\Database\Query\Builder
     *
     * @throws \InvalidArgumentException
     */
    private function table(): Builder
    {
        return $this->connection()->table(TableNames::of(TableNames::ATTEMPTS));
    }

    /**
     * The storage connection.
     *
     * @return \Illuminate\Database\Connection
     *
     * @throws \InvalidArgumentException
     */
    private function connection(): Connection
    {
        return DB::connection(StorageConnection::name());
    }

    /**
     * Format a Unix time as the storage connection stores times, in the
     * application's timezone.
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
     * A stored count as an integer.
     *
     * @param  mixed  $value
     * @return int
     */
    private static function integer(mixed $value): int
    {
        return is_numeric($value) ? (int) $value : 0;
    }

    /**
     * A stored time, read in the application's timezone, as a Unix time; the
     * epoch for anything that is not a time, so it counts as ended.
     *
     * @param  mixed  $value
     * @return int
     */
    private static function timestamp(mixed $value): int
    {
        return is_string($value) && $value !== '' ? CarbonImmutable::parse($value, date_default_timezone_get())->getTimestamp() : 0;
    }
}
