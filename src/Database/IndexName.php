<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Database;

/**
 * Names the shipped migrations give their indexes: the table's name and a
 * suffix naming what the index is for, or, when that would pass the 63
 * characters PostgreSQL keeps (MySQL keeps 64), the start of the table's name
 * and a hash of the whole, so a long configured table name still gives one
 * index name, the same on every run, that every engine accepts.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class IndexName
{
    /** @var int The longest identifier every supported engine keeps. */
    private const int LONGEST = 63;

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * The name of the table's index with the given suffix (such as
     * `_owner_index`).
     *
     * @param  string  $table
     * @param  string  $suffix
     * @return string
     */
    public static function for(string $table, string $suffix): string
    {
        $index = $table . $suffix;

        if (strlen($index) <= self::LONGEST) {
            return $index;
        }

        $hash = substr(hash('sha256', $table), 0, 8);

        return substr($table, 0, self::LONGEST - strlen($suffix) - strlen($hash) - 1) . '_' . $hash . $suffix;
    }
}
