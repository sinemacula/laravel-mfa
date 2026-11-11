<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Database;

/**
 * Index names for the shipped migrations, shortened with a hash of the table
 * name when they would pass PostgreSQL's 63 characters.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class IndexName
{
    /** @var int PostgreSQL's limit; MySQL keeps 64. */
    private const int LONGEST = 63;

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
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
