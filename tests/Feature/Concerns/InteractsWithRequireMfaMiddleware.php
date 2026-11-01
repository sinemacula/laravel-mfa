<?php

declare(strict_types = 1);

namespace Tests\Feature\Concerns;

use Illuminate\Http\Request;
use SineMacula\Laravel\Mfa\Http\Middleware\RequireMfa;
use SineMacula\Laravel\Mfa\Models\Factor;
use Symfony\Component\HttpFoundation\Response;
use Tests\Fixtures\Drivers\AuthenticatorApp;
use Tests\Fixtures\Identities\TestUser;

/**
 * Shared scaffolding for the RequireMfa middleware test family.
 *
 * Centralises the middleware invocation helper and the "enrol a TOTP factor for
 * a fresh user" fixture so the enforcement-matrix and step-up-parser test
 * classes stay focused on their respective subjects.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait InteractsWithRequireMfaMiddleware
{
    /**
     * Drive the middleware with the given route-middleware param and report
     * whether the inner handler was reached.
     *
     * @param  ?string  $maxAgeMinutes
     * @return bool
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    protected function runMiddleware(?string $maxAgeMinutes): bool
    {
        $middleware = $this->container()->make(
            RequireMfa::class,
        );

        $reached = false;
        $middleware->handle(
            $this->container()->make(Request::class),
            static function () use (&$reached): Response {
                $reached = true;

                return new Response('ok');
            },
            $maxAgeMinutes,
        );

        return $reached;
    }

    /**
     * Enrol a fresh TOTP factor and return the [user, factor, code] triple.
     *
     * @param  string  $email
     * @return array{0: \Tests\Fixtures\Identities\TestUser, 1: \SineMacula\Laravel\Mfa\Models\Factor, 2: string}
     */
    protected function enrollTotp(string $email = 'totp-mw@example.test'): array
    {
        $user = TestUser::create([
            'email'       => $email,
            'mfa_enabled' => true,
        ]);
        $this->actingAs($user);

        /** @var \SineMacula\Laravel\Mfa\Models\Factor $factor */
        $factor = Factor::create([
            ...AuthenticatorApp::FACTOR,
            'authenticatable_type' => $user::class,
            'authenticatable_id'   => (string) $user->id,
        ]);

        return [$user, $factor, AuthenticatorApp::code($factor)];
    }
}
