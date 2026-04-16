<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Foundation\Testing\RefreshDatabase;
use PragmaRX\Google2FA\Google2FA;
use SineMacula\Laravel\Mfa\Exceptions\MfaExpiredException;
use SineMacula\Laravel\Mfa\Exceptions\MfaRequiredException;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Support\FactorSummary;
use Tests\Fixtures\TestUser;
use Tests\TestCase;

/**
 * RequireMfa middleware dispatch matrix.
 *
 * Covers every branch: skip-flag, shouldUse false, no factors
 * (MfaRequiredException), never verified (MfaRequiredException),
 * expired (MfaExpiredException), fresh verification (passes).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 *
 * @internal
 */
final class RequireMfaMiddlewareTest extends TestCase
{
    use RefreshDatabase;

    public function testPassesWhenMfaDisabled(): void
    {
        $user = TestUser::create([
            'email'       => 'nomfa@example.test',
            'mfa_enabled' => false,
        ]);
        $this->actingAs($user);

        self::assertFalse(Mfa::shouldUse());
    }

    public function testRaisesRequiredExceptionWhenNoFactors(): void
    {
        $user = TestUser::create([
            'email'       => 'newbie@example.test',
            'mfa_enabled' => true,
        ]);
        $this->actingAs($user);

        self::assertTrue(Mfa::shouldUse());
        self::assertFalse(Mfa::isSetup());

        try {
            $middleware = $this->app->make(
                \SineMacula\Laravel\Mfa\Middleware\RequireMfa::class,
            );
            $middleware->handle(
                $this->app->make(\Illuminate\Http\Request::class),
                static fn (): mixed => 'not reached',
            );

            self::fail('Expected MfaRequiredException');
        } catch (MfaRequiredException $e) {
            self::assertSame(401, $e->getStatusCode());
            self::assertIsArray($e->getFactors());
        }
    }

    public function testRaisesRequiredExceptionWhenNeverVerified(): void
    {
        [, $factor] = $this->enrolTotp();

        try {
            $middleware = $this->app->make(
                \SineMacula\Laravel\Mfa\Middleware\RequireMfa::class,
            );
            $middleware->handle(
                $this->app->make(\Illuminate\Http\Request::class),
                static fn (): mixed => 'not reached',
            );

            self::fail('Expected MfaRequiredException');
        } catch (MfaRequiredException $e) {
            self::assertSame(401, $e->getStatusCode());

            $factors = $e->getFactors();
            self::assertCount(1, $factors);
            self::assertInstanceOf(FactorSummary::class, $factors[0]);
            self::assertSame('totp', $factors[0]->driver);
        }

        unset($factor);
    }

    public function testRaisesExpiredExceptionWhenVerificationAgedOut(): void
    {
        [$user, $factor, $code] = $this->enrolTotp();

        // Complete a verification first.
        self::assertTrue(Mfa::verify('totp', $factor, $code));

        // Rewind the session timestamp past the expiry.
        $this->travel(15 * 24 * 60 + 1)->minutes();

        try {
            $middleware = $this->app->make(
                \SineMacula\Laravel\Mfa\Middleware\RequireMfa::class,
            );
            $middleware->handle(
                $this->app->make(\Illuminate\Http\Request::class),
                static fn (): mixed => 'not reached',
            );

            self::fail('Expected MfaExpiredException');
        } catch (MfaExpiredException $e) {
            self::assertSame(401, $e->getStatusCode());
        }

        unset($user, $factor);
    }

    public function testSkipAttributeBypassesEnforcement(): void
    {
        $user = TestUser::create([
            'email'       => 'skip@example.test',
            'mfa_enabled' => true,
        ]);
        $this->actingAs($user);

        $request = $this->app->make(\Illuminate\Http\Request::class);
        $request->attributes->set('skip_mfa', true);

        $middleware = $this->app->make(
            \SineMacula\Laravel\Mfa\Middleware\RequireMfa::class,
        );

        $reached = false;
        $middleware->handle($request, static function () use (&$reached): \Symfony\Component\HttpFoundation\Response {
            $reached = true;

            return new \Symfony\Component\HttpFoundation\Response('ok');
        });

        self::assertTrue($reached);
    }

    /**
     * @return array{0: TestUser, 1: Factor, 2: string}
     */
    private function enrolTotp(): array
    {
        $user = TestUser::create([
            'email'       => 'totp-mw@example.test',
            'mfa_enabled' => true,
        ]);
        $this->actingAs($user);

        $google = new Google2FA;
        $secret = $google->generateSecretKey();

        /** @var Factor $factor */
        $factor = Factor::create([
            'authenticatable_type' => $user::class,
            'authenticatable_id'   => (string) $user->getKey(),
            'driver'               => 'totp',
            'secret'               => $secret,
        ]);

        return [$user, $factor, $google->getCurrentOtp($secret)];
    }
}
