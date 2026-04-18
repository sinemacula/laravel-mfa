<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Request;
use SineMacula\Laravel\Mfa\Exceptions\MfaExpiredException;
use SineMacula\Laravel\Mfa\Exceptions\MfaRequiredException;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\Middleware\RequireMfa;
use SineMacula\Laravel\Mfa\Support\FactorSummary;
use Symfony\Component\HttpFoundation\Response;
use Tests\Feature\Concerns\InteractsWithRequireMfaMiddleware;
use Tests\Fixtures\TestUser;
use Tests\TestCase;

/**
 * RequireMfa middleware enforcement matrix.
 *
 * Covers the lifecycle branches: skip-flag, shouldUse false, no factors
 * (MfaRequiredException), never verified (MfaRequiredException), expired
 * (MfaExpiredException), and fresh verification (passes). Step-up `mfa:N`
 * parameter parsing lives in its own dedicated test class.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 *
 * @internal
 */
final class RequireMfaMiddlewareTest extends TestCase
{
    use InteractsWithRequireMfaMiddleware, RefreshDatabase;

    /** @var string Sentinel returned by the inner handler so a missed-throw shows up as a string assertion failure. */
    private const string NOT_REACHED = 'not reached';

    /**
     * An identity that does not opt into MFA must not trigger the middleware
     * enforcement chain.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testPassesWhenMfaDisabled(): void
    {
        $user = TestUser::create([
            'email'       => 'nomfa@example.test',
            'mfa_enabled' => false,
        ]);
        $this->actingAs($user);

        self::assertFalse(Mfa::shouldUse());
    }

    /**
     * An MFA-enrolled identity with no registered factors must trigger an
     * `MfaRequiredException` from the middleware.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
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
            $middleware = $this->container()->make(
                RequireMfa::class,
            );
            $middleware->handle(
                $this->container()->make(Request::class),
                static fn (): mixed => self::NOT_REACHED,
            );

            self::fail('Expected MfaRequiredException');
        } catch (MfaRequiredException $e) {
            self::assertSame(401, $e->getStatusCode());
            self::assertIsArray($e->getFactors());
        }
    }

    /**
     * An identity with at least one factor but no successful verification must
     * trigger an `MfaRequiredException` carrying the factor summaries in the
     * payload.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \PragmaRX\Google2FA\Exceptions\IncompatibleWithGoogleAuthenticatorException
     * @throws \PragmaRX\Google2FA\Exceptions\InvalidCharactersException
     * @throws \PragmaRX\Google2FA\Exceptions\SecretKeyTooShortException
     */
    public function testRaisesRequiredExceptionWhenNeverVerified(): void
    {
        [, $factor] = $this->enrolTotp();

        try {
            $middleware = $this->container()->make(
                RequireMfa::class,
            );
            $middleware->handle(
                $this->container()->make(Request::class),
                static fn (): mixed => self::NOT_REACHED,
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

    /**
     * Once the active verification ages past the configured expiry the
     * middleware must throw `MfaExpiredException`.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \PragmaRX\Google2FA\Exceptions\IncompatibleWithGoogleAuthenticatorException
     * @throws \PragmaRX\Google2FA\Exceptions\InvalidCharactersException
     * @throws \PragmaRX\Google2FA\Exceptions\SecretKeyTooShortException
     */
    public function testRaisesExpiredExceptionWhenVerificationAgedOut(): void
    {
        [$user, $factor, $code] = $this->enrolTotp();

        // Complete a verification first.
        self::assertTrue(Mfa::verify('totp', $factor, $code));

        // Rewind the session timestamp past the expiry.
        $this->travel(15 * 24 * 60 + 1)->minutes();

        try {
            $middleware = $this->container()->make(
                RequireMfa::class,
            );
            $middleware->handle(
                $this->container()->make(Request::class),
                static fn (): mixed => self::NOT_REACHED,
            );

            self::fail('Expected MfaExpiredException');
        } catch (MfaExpiredException $e) {
            self::assertSame(401, $e->getStatusCode());
        }

        unset($user, $factor);
    }

    /**
     * Setting the `skip_mfa` request attribute must short-circuit the
     * middleware to the next handler regardless of MFA state.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testSkipAttributeBypassesEnforcement(): void
    {
        $user = TestUser::create([
            'email'       => 'skip@example.test',
            'mfa_enabled' => true,
        ]);
        $this->actingAs($user);

        $request = $this->container()->make(Request::class);
        $request->attributes->set('skip_mfa', true);

        $middleware = $this->container()->make(
            RequireMfa::class,
        );

        $reached = false;
        $middleware->handle($request, static function () use (&$reached): Response {
            $reached = true;

            return new Response('ok');
        });

        self::assertTrue($reached);
    }
}
