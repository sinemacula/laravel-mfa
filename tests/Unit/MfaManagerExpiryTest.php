<?php

declare(strict_types = 1);

namespace Tests\Unit;

use Carbon\Carbon;
use Illuminate\Config\Repository;
use SineMacula\Laravel\Mfa\Contracts\MfaVerificationStore;
use Tests\Fixtures\TestUser;
use Tests\Unit\Concerns\InteractsWithMfaManagerState;

/**
 * Unit tests for `MfaManager::hasExpired()`.
 *
 * Split out from the broader state-test family so each subject stays under the
 * project's max-methods-per-class threshold. Covers every branch of the expiry
 * decision: identity presence, prior verification presence, the
 * configured-vs-explicit window, the zero / negative / future-dated edge cases,
 * and the malformed / numeric-string config paths.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 *
 * @internal
 */
final class MfaManagerExpiryTest extends MfaManagerTestCase
{
    use InteractsWithMfaManagerState;

    /**
     * Without an identity verification is always treated as expired.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testHasExpiredReturnsTrueWhenNoIdentity(): void
    {
        self::assertTrue($this->manager()->hasExpired());
    }

    /**
     * An identity with no prior verification record should be treated as
     * expired so the consumer is forced to verify.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testHasExpiredReturnsTrueWhenNoPriorVerification(): void
    {
        $user = TestUser::query()->create(['email' => 'g@example.com']);

        $this->actingAs($user);

        $this->container()->instance(
            MfaVerificationStore::class,
            $this->nullStore(),
        );

        self::assertTrue($this->manager()->hasExpired());
    }

    /**
     * Omitting the explicit expiry argument should fall back to the configured
     * `mfa.default_expiry` value.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testHasExpiredUsesConfiguredDefaultExpiryWhenParameterOmitted(): void
    {
        $user = TestUser::query()->create(['email' => 'h@example.com']);

        $this->actingAs($user);

        $config = app(Repository::class);
        $config->set('mfa.default_expiry', 60);

        $this->container()->instance(
            MfaVerificationStore::class,
            $this->fixedStore(Carbon::now()->subMinutes(30)),
        );

        self::assertFalse($this->manager()->hasExpired());
    }

    /**
     * A recent verification with an explicit expiry should be treated as still
     * valid.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testHasExpiredReturnsFalseForRecentVerificationWithExplicitExpiry(): void
    {
        $user = TestUser::query()->create(['email' => 'i@example.com']);

        $this->actingAs($user);

        $this->container()->instance(
            MfaVerificationStore::class,
            $this->fixedStore(Carbon::now()->subMinutes(5)),
        );

        self::assertFalse($this->manager()->hasExpired(60));
    }

    /**
     * An explicit expiry of zero minutes should immediately expire any prior
     * verification.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testHasExpiredReturnsTrueWhenExplicitExpiryIsZero(): void
    {
        $user = TestUser::query()->create(['email' => 'j@example.com']);

        $this->actingAs($user);

        $this->container()->instance(
            MfaVerificationStore::class,
            $this->fixedStore(Carbon::now()->subMinutes(1)),
        );

        self::assertTrue($this->manager()->hasExpired(0));
    }

    /**
     * A negative explicit expiry must be treated identically to zero.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testHasExpiredReturnsTrueWhenExplicitExpiryIsNegative(): void
    {
        $user = TestUser::query()->create(['email' => 'k@example.com']);

        $this->actingAs($user);

        $this->container()->instance(
            MfaVerificationStore::class,
            $this->fixedStore(Carbon::now()->subMinutes(1)),
        );

        self::assertTrue($this->manager()->hasExpired(-5));
    }

    /**
     * A future-dated verification timestamp must be rejected as a clock-skew
     * defence and treated as expired.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testHasExpiredReturnsTrueForFutureDatedVerification(): void
    {
        $user = TestUser::query()->create(['email' => 'l@example.com']);

        $this->actingAs($user);

        // Clock-skew defence: a store that reports a verification in the future
        // should not be trusted as "still valid".
        $this->container()->instance(
            MfaVerificationStore::class,
            $this->fixedStore(Carbon::now()->addMinutes(30)),
        );

        self::assertTrue($this->manager()->hasExpired(60));
    }

    /**
     * Once the elapsed minutes exceed the expiry budget the verification should
     * expire.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testHasExpiredReturnsTrueWhenElapsedExceedsExpiry(): void
    {
        $user = TestUser::query()->create(['email' => 'm@example.com']);

        $this->actingAs($user);

        $this->container()->instance(
            MfaVerificationStore::class,
            $this->fixedStore(Carbon::now()->subMinutes(120)),
        );

        self::assertTrue($this->manager()->hasExpired(60));
    }

    /**
     * The expiry comparison is `elapsed > window` (strict greater-than), so a
     * verification recorded exactly `window` minutes ago is still valid. Pins
     * the inclusive boundary so a regression to `>=` is caught.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testHasExpiredReturnsFalseAtExactWindowBoundary(): void
    {
        $user = TestUser::query()->create(['email' => 'boundary@example.com']);

        $this->actingAs($user);

        // Freeze the clock so the elapsed minutes are exactly the window — no
        // rounding noise from the wall clock advancing mid-test.
        $this->travelTo(Carbon::parse('2026-01-01T12:00:00Z'));

        $this->container()->instance(
            MfaVerificationStore::class,
            $this->fixedStore(Carbon::parse('2026-01-01T11:00:00Z')),
        );

        self::assertFalse(
            $this->manager()->hasExpired(60),
            'a verification recorded exactly `window` minutes ago must still be valid',
        );

        $this->travelBack();
    }

    /**
     * One minute past the window the verification must expire. Pairs with the
     * boundary test above to pin the strictly-greater-than semantics from both
     * sides.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testHasExpiredReturnsTrueOneMinuteAfterWindowBoundary(): void
    {
        $user = TestUser::query()->create(['email' => 'past-boundary@example.com']);

        $this->actingAs($user);

        $this->travelTo(Carbon::parse('2026-01-01T12:00:00Z'));

        $this->container()->instance(
            MfaVerificationStore::class,
            $this->fixedStore(Carbon::parse('2026-01-01T10:59:00Z')),
        );

        self::assertTrue(
            $this->manager()->hasExpired(60),
            'a verification one minute past the window must expire',
        );

        $this->travelBack();
    }

    /**
     * A non-numeric `mfa.default_expiry` config value should be coerced to
     * zero, expiring any prior verification.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testHasExpiredDefaultsToFallbackExpiryWhenConfigIsNonNumeric(): void
    {
        $user = TestUser::query()->create(['email' => 'n@example.com']);

        $this->actingAs($user);

        $config = app(Repository::class);
        $config->set('mfa.default_expiry', 'not-a-number');

        $this->container()->instance(
            MfaVerificationStore::class,
            $this->fixedStore(Carbon::now()->subMinute()),
        );

        // A non-numeric config falls back to 0 via the manager's
        // `resolveIntConfig()` defence (with `malformedFallback: 0`), meaning
        // any prior verification is treated as expired.
        self::assertTrue($this->manager()->hasExpired());
    }

    /**
     * A numeric-string `mfa.default_expiry` config value should be coerced to
     * an int and respected.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testHasExpiredCoercesNumericStringConfigToInt(): void
    {
        $user = TestUser::query()->create(['email' => 'o@example.com']);

        $this->actingAs($user);

        $config = app(Repository::class);
        $config->set('mfa.default_expiry', '60');

        $this->container()->instance(
            MfaVerificationStore::class,
            $this->fixedStore(Carbon::now()->subMinutes(10)),
        );

        self::assertFalse($this->manager()->hasExpired());
    }
}
