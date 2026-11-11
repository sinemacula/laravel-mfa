<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Database;

use Illuminate\Database\Query\Builder;

/**
 * Deletes in limited statements, so pruning a large table neither holds locks
 * for long nor builds one huge transaction. No model event fires.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class BoundedDelete
{
    /** @var int Rows per statement. */
    public const int LIMIT = 1000;

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * @param  \Illuminate\Database\Query\Builder  $query
     * @return int
     *
     * @imperative
     */
    public static function run(Builder $query): int
    {
        $total = 0;

        $query->limit(self::LIMIT);

        do {
            $deleted = $query->delete();
            $total += $deleted;
        } while ($deleted === self::LIMIT);

        return $total;
    }
}
