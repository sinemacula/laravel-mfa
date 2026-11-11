<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Context;

use Illuminate\Contracts\Foundation\Application;
use SineMacula\Laravel\Mfa\Contracts\ActiveStateResolver;
use SineMacula\Laravel\Mfa\Contracts\PendingSessionResolver;
use SineMacula\Laravel\Mfa\Contracts\SubjectTypeResolver;

/**
 * Binds the default seams that say who a request is for, each only if an
 * authentication adapter has not bound its own.
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
