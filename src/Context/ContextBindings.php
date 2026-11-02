<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Context;

use Illuminate\Contracts\Foundation\Application;
use SineMacula\Laravel\Mfa\Contracts\PendingSessionResolver;
use SineMacula\Laravel\Mfa\Contracts\SubjectTypeResolver;

/**
 * Registers the defaults of the seams that say who a request is for: no pending
 * sessions (`NoPendingSessionResolver`), and a person read from the identity
 * contract (`IdentityContractSubjectType`). An adapter over an authentication
 * layer rebinds either in its own service provider.
 *
 * Neither default keeps state between calls, so each is shared.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ContextBindings
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Register the default pending session and subject type resolvers.
     *
     * @param  \Illuminate\Contracts\Foundation\Application  $app
     * @return void
     */
    public static function register(Application $app): void
    {
        $app->singleton(PendingSessionResolver::class, NoPendingSessionResolver::class);
        $app->singleton(SubjectTypeResolver::class, IdentityContractSubjectType::class);
    }
}
