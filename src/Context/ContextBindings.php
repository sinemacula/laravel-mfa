<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Context;

use Illuminate\Contracts\Foundation\Application;
use SineMacula\Laravel\Mfa\Contracts\ActiveStateResolver;
use SineMacula\Laravel\Mfa\Contracts\PendingSessionResolver;
use SineMacula\Laravel\Mfa\Contracts\SubjectTypeResolver;

/**
 * Registers the defaults of the seams that say who a request is for: no pending
 * sessions (`NoPendingSessionResolver`), and a person and an active state read
 * from the identity contract (`IdentityContractSubjectType` and
 * `IdentityContractActiveState`). An adapter over an authentication layer
 * rebinds any of them in its own service provider.
 *
 * No default keeps state between calls, and each is built when it is asked for,
 * on the application serving at the time.
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
     * Register the default pending session, subject type and active state
     * resolvers.
     *
     * @param  \Illuminate\Contracts\Foundation\Application  $app
     * @return void
     */
    public static function register(Application $app): void
    {
        $app->bindIf(PendingSessionResolver::class, NoPendingSessionResolver::class);
        $app->bindIf(SubjectTypeResolver::class, IdentityContractSubjectType::class);
        $app->bindIf(ActiveStateResolver::class, IdentityContractActiveState::class);
    }
}
