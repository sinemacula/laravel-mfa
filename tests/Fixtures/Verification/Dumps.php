<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Verification;

use Symfony\Component\VarDumper\Cloner\VarCloner;
use Symfony\Component\VarDumper\Dumper\CliDumper;

/**
 * Every way a value can be dumped, so a test can assert none of them shows a
 * secret: `print_r`, `var_dump`, `var_export`, an array cast and Symfony's
 * VarDumper behind Laravel's `dump()` and `dd()`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class Dumps
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * What each way of dumping the value shows, keyed by the way.
     *
     * @param  object  $value
     * @return array<string, string>
     */
    public static function of(object $value): array
    {
        ob_start();

        var_dump($value); // phpcs:ignore SineMaculaLaravel.Debug.DisallowDebugStatements.Found

        $dumped = (string) ob_get_clean();

        return [
            'print_r'    => print_r($value, true),
            'var_dump'   => $dumped,
            'var_export' => var_export($value, true),
            'array cast' => print_r((array) $value, true),
            'VarDumper'  => (string) (new CliDumper)->dump((new VarCloner)->cloneVar($value), true),
        ];
    }
}
