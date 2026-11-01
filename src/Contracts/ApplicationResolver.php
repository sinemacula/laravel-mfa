<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Contracts;

use Illuminate\Http\Request;

/**
 * Application resolver contract.
 *
 * Names the application a request is for, the key factor types, requirements,
 * limits and freshness are configured under. Without an authentication layer
 * that knows the application, it is the name of the guard that authenticated
 * the request.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface ApplicationResolver
{
    /**
     * The application the request is for.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return string
     */
    public function resolve(Request $request): string;
}
