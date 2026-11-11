<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Testing\Seams;

use PHPUnit\Framework\Assert;

/**
 * What every `IdentityRequirement` and `TenantRequirement` must guarantee: the
 * same question answers the same requirement whatever was asked in between.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
final class RequirementSeamContract
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * `$ask` must answer the same again at once and after `$askAnother`.
     *
     * @param  \Closure(): \SineMacula\Laravel\Mfa\Requirements\Requirement  $ask
     * @param  \Closure(): \SineMacula\Laravel\Mfa\Requirements\Requirement  $askAnother
     * @return void
     */
    public static function assertKeepsNoStateBetweenCalls(\Closure $ask, \Closure $askAnother): void
    {
        $first = $ask()->toArray();

        Assert::assertSame($first, $ask()->toArray(), 'A requirement seam must answer the same question the same way each time it is asked.');

        $askAnother();

        Assert::assertSame($first, $ask()->toArray(), 'A requirement seam must answer the same question the same way, whatever was asked in between.');
    }
}
