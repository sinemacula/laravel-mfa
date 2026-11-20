<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Http;

use Illuminate\Routing\Controllers\HasMiddleware;
use Illuminate\Routing\Controllers\Middleware;

/**
 * Marks only its `verify` action exempt, through controller middleware.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ExemptingController implements HasMiddleware
{
    /**
     * @return list<\Illuminate\Routing\Controllers\Middleware>
     */
    #[\Override]
    public static function middleware(): array
    {
        return [new Middleware('mfa.exempt', only: ['verify'])];
    }

    /**
     * @return string
     */
    public function verify(): string
    {
        return 'reached';
    }

    /**
     * @return string
     */
    public function settings(): string
    {
        return 'reached';
    }
}
