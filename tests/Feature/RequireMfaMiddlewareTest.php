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

    public function testStepUpPassesWhenVerificationIsWithinMaxAge(): void
    {
        [, $factor, $code] = $this->enrolTotp();

        self::assertTrue(Mfa::verify('totp', $factor, $code));

        $this->travel(4)->minutes();

        $reached = $this->runMiddleware(maxAgeMinutes: '5');

        self::assertTrue($reached);
    }

    public function testStepUpThrowsExpiredWhenVerificationOlderThanMaxAge(): void
    {
        [, $factor, $code] = $this->enrolTotp();

        self::assertTrue(Mfa::verify('totp', $factor, $code));

        $this->travel(6)->minutes();

        $this->expectException(MfaExpiredException::class);

        $this->runMiddleware(maxAgeMinutes: '5');
    }

    public function testStepUpZeroAlwaysThrowsEvenForFreshVerification(): void
    {
        [, $factor, $code] = $this->enrolTotp();

        self::assertTrue(Mfa::verify('totp', $factor, $code));

        $this->expectException(MfaExpiredException::class);

        $this->runMiddleware(maxAgeMinutes: '0');
    }

    public function testStepUpOverridesShorterDefaultExpiry(): void
    {
        // The default config expiry is 14 days; force it to 1 minute so
        // we can prove that an explicit `mfa:60` parameter wins by
        // letting a verification 30 minutes old still pass.
        config()->set('mfa.default_expiry', 1);

        [, $factor, $code] = $this->enrolTotp();

        self::assertTrue(Mfa::verify('totp', $factor, $code));

        $this->travel(30)->minutes();

        $reached = $this->runMiddleware(maxAgeMinutes: '60');

        self::assertTrue($reached);
    }

    public function testStepUpRejectsNonNumericParameter(): void
    {
        $user = TestUser::create([
            'email'       => 'badparam@example.test',
            'mfa_enabled' => true,
        ]);
        $this->actingAs($user);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('RequireMfa middleware max-age parameter must be a non-negative integer');

        $this->runMiddleware(maxAgeMinutes: 'abc');
    }

    public function testStepUpRejectsNegativeParameter(): void
    {
        $user = TestUser::create([
            'email'       => 'negparam@example.test',
            'mfa_enabled' => true,
        ]);
        $this->actingAs($user);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('RequireMfa middleware max-age parameter must be a non-negative integer');

        $this->runMiddleware(maxAgeMinutes: '-1');
    }

    public function testStepUpRejectsFractionalParameter(): void
    {
        $user = TestUser::create([
            'email'       => 'fracparam@example.test',
            'mfa_enabled' => true,
        ]);
        $this->actingAs($user);

        $this->expectException(\InvalidArgumentException::class);

        $this->runMiddleware(maxAgeMinutes: '1.5');
    }

    /**
     * Tighter parser checks: scientific notation, leading sign,
     * surrounding whitespace, and empty string must all be rejected.
     * `is_numeric` would silently coerce these to ints, which is the
     * opposite of what a route definition needs.
     *
     * @return void
     */
    public function testStepUpRejectsLooselyNumericParameters(): void
    {
        $user = TestUser::create([
            'email'       => 'loose@example.test',
            'mfa_enabled' => true,
        ]);
        $this->actingAs($user);

        $candidates = ['1e2', '+5', ' 5', '5 ', ''];
        $rejected   = [];

        foreach ($candidates as $candidate) {
            try {
                $this->runMiddleware(maxAgeMinutes: $candidate);
            } catch (\InvalidArgumentException) {
                $rejected[] = $candidate;
            }
        }

        self::assertSame($candidates, $rejected);
    }

    /**
     * Drive the middleware with the given route-middleware param and
     * report whether the inner handler was reached.
     *
     * @param  ?string  $maxAgeMinutes
     * @return bool
     */
    private function runMiddleware(?string $maxAgeMinutes): bool
    {
        $middleware = $this->app->make(
            \SineMacula\Laravel\Mfa\Middleware\RequireMfa::class,
        );

        $reached = false;
        $middleware->handle(
            $this->app->make(\Illuminate\Http\Request::class),
            static function () use (&$reached): \Symfony\Component\HttpFoundation\Response {
                $reached = true;

                return new \Symfony\Component\HttpFoundation\Response('ok');
            },
            $maxAgeMinutes,
        );

        return $reached;
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
