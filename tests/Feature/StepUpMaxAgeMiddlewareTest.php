<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Foundation\Testing\RefreshDatabase;
use SineMacula\Laravel\Mfa\Exceptions\MfaExpiredException;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use Tests\Feature\Concerns\InteractsWithRequireMfaMiddleware;
use Tests\Fixtures\TestUser;
use Tests\TestCase;

/**
 * RequireMfa middleware step-up `mfa:N` parameter parsing matrix.
 *
 * Split out from the middleware's enforcement-matrix tests so each
 * cohesive subject — lifecycle enforcement vs. route-middleware
 * parameter parsing — has a focused suite.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 *
 * @internal
 */
final class StepUpMaxAgeMiddlewareTest extends TestCase
{
    use InteractsWithRequireMfaMiddleware;
    use RefreshDatabase;

    /**
     * Step-up middleware: a verification within the configured
     * max-age must pass through.
     *
     * @return void
     */
    public function testStepUpPassesWhenVerificationIsWithinMaxAge(): void
    {
        [, $factor, $code] = $this->enrolTotp();

        self::assertTrue(Mfa::verify('totp', $factor, $code));

        $this->travel(4)->minutes();

        $reached = $this->runMiddleware(maxAgeMinutes: '5');

        self::assertTrue($reached);
    }

    /**
     * Step-up middleware: a verification older than the configured
     * max-age must throw `MfaExpiredException`.
     *
     * @return void
     */
    public function testStepUpThrowsExpiredWhenVerificationOlderThanMaxAge(): void
    {
        [, $factor, $code] = $this->enrolTotp();

        self::assertTrue(Mfa::verify('totp', $factor, $code));

        $this->travel(6)->minutes();

        $this->expectException(MfaExpiredException::class);

        $this->runMiddleware(maxAgeMinutes: '5');
    }

    /**
     * Step-up middleware: a max-age of zero must always throw,
     * regardless of how recent the verification was.
     *
     * @return void
     */
    public function testStepUpZeroAlwaysThrowsEvenForFreshVerification(): void
    {
        [, $factor, $code] = $this->enrolTotp();

        self::assertTrue(Mfa::verify('totp', $factor, $code));

        $this->expectException(MfaExpiredException::class);

        $this->runMiddleware(maxAgeMinutes: '0');
    }

    /**
     * Step-up middleware: an explicit `mfa:N` parameter must
     * override a shorter `default_expiry` config so the per-route
     * window wins.
     *
     * @return void
     */
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

    /**
     * Step-up middleware: a non-numeric `mfa:N` parameter must
     * surface a clear `InvalidArgumentException`.
     *
     * @return void
     */
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

    /**
     * Step-up middleware: a negative `mfa:N` parameter must surface
     * a clear `InvalidArgumentException`.
     *
     * @return void
     */
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

    /**
     * Step-up middleware: a fractional `mfa:N` parameter must
     * surface a clear `InvalidArgumentException`.
     *
     * @return void
     */
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
     * Loosely-numeric parameter inputs that `is_numeric` would accept
     * but a route max-age must reject.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function looselyNumericParameterProvider(): iterable
    {
        yield from [
            'scientific notation' => ['1e2'],
            'leading plus'        => ['+5'],
            'leading whitespace'  => [' 5'],
            'trailing whitespace' => ['5 '],
            'empty string'        => [''],
        ];
    }

    /**
     * Tighter parser checks: scientific notation, leading sign,
     * surrounding whitespace, and empty string must all be rejected.
     * `is_numeric` would silently coerce these to ints, which is the
     * opposite of what a route definition needs.
     *
     * @param  string  $candidate
     * @return void
     */
    #[\PHPUnit\Framework\Attributes\DataProvider('looselyNumericParameterProvider')]
    public function testStepUpRejectsLooselyNumericParameter(string $candidate): void
    {
        $user = TestUser::create([
            'email'       => 'loose@example.test',
            'mfa_enabled' => true,
        ]);
        $this->actingAs($user);

        $this->expectException(\InvalidArgumentException::class);

        $this->runMiddleware(maxAgeMinutes: $candidate);
    }
}
