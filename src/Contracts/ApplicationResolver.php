<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Contracts;

use Illuminate\Http\Request;

/**
 * Names the application a request is for, the key its factor types,
 * requirements, limits and freshness are configured under.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface ApplicationResolver
{
    /**
     * @param  \Illuminate\Http\Request  $request
     * @return string
     */
    public function resolve(Request $request): string;
}
