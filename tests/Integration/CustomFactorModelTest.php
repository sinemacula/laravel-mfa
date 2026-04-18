<?php

declare(strict_types = 1);

namespace Tests\Integration;

use Illuminate\Foundation\Testing\RefreshDatabase;
use SineMacula\Laravel\Mfa\Contracts\EloquentFactor;
use SineMacula\Laravel\Mfa\Exceptions\InvalidFactorModelException;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\Models\Factor;
use Tests\Fixtures\CustomFactor;
use Tests\TestCase;

/**
 * `mfa.factor.model` configuration seam.
 *
 * Closes the documented configurable-factor-model contract: the package's
 * `factorModel()` accessor must honour `config('mfa.factor.model')` and reject
 * misconfiguration loudly rather than silently falling back to the shipped
 * default.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 *
 * @internal
 */
final class CustomFactorModelTest extends TestCase
{
    use RefreshDatabase;

    /**
     * With no config override, `Mfa::factorModel()` returns the shipped
     * `Factor` model so consumers without a custom subclass keep the existing
     * default behaviour.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testReturnsShippedFactorModelByDefault(): void
    {
        // A null value (env var unset, key cleared) must fall back to the
        // shipped model — matches a fresh install with no override.
        config()->set('mfa.factor.model', null);

        self::assertSame(Factor::class, Mfa::factorModel());
    }

    /**
     * Setting `mfa.factor.model` to a custom subclass implementing the
     * `EloquentFactor` contract returns the configured class.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testReturnsConfiguredCustomFactorModel(): void
    {
        config()->set('mfa.factor.model', CustomFactor::class);

        self::assertSame(CustomFactor::class, Mfa::factorModel());
        self::assertSame(CustomFactor::FIXTURE_TAG, 'custom-factor-fixture');
    }

    /**
     * The configured custom model must be returned as a class string compatible
     * with `morphMany(Mfa::factorModel(), ...)` — i.e. an instance of the
     * configured class actually implements the `EloquentFactor` contract the
     * package writes through.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testConfiguredModelInstanceSatisfiesEloquentFactorContract(): void
    {
        config()->set('mfa.factor.model', CustomFactor::class);

        $resolved = Mfa::factorModel();
        $instance = new $resolved;

        self::assertInstanceOf(EloquentFactor::class, $instance);
        self::assertInstanceOf(CustomFactor::class, $instance);
    }

    /**
     * A non-string config value (number, array) must throw rather than silently
     * flowing through to a `class_exists` call that would emit a soft warning.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testRejectsNonStringConfigValue(): void
    {
        config()->set('mfa.factor.model', 123);

        $this->expectException(InvalidFactorModelException::class);
        $this->expectExceptionMessage('must be a class string');

        Mfa::factorModel();
    }

    /**
     * An empty-string config value must throw — empty implies "intentionally
     * cleared" but is never a valid model class.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testRejectsEmptyStringConfigValue(): void
    {
        config()->set('mfa.factor.model', '');

        $this->expectException(InvalidFactorModelException::class);
        $this->expectExceptionMessage('must be a class string');

        Mfa::factorModel();
    }

    /**
     * A class name that does not exist must throw with a message naming the
     * missing class so the deployment-time misconfiguration is obvious in the
     * resulting stack trace.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testRejectsNonExistentClass(): void
    {
        config()->set('mfa.factor.model', 'App\DoesNotExistFactor');

        $this->expectException(InvalidFactorModelException::class);
        $this->expectExceptionMessage('App\DoesNotExistFactor');

        Mfa::factorModel();
    }

    /**
     * A class that exists but does not implement `EloquentFactor` must throw —
     * the contract is the seam consumers integrate against, and a class that
     * does not satisfy it would crash at the first call site instead of at
     * boot.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testRejectsClassThatDoesNotImplementEloquentFactor(): void
    {
        config()->set('mfa.factor.model', \stdClass::class);

        $this->expectException(InvalidFactorModelException::class);
        $this->expectExceptionMessage('must extend');

        Mfa::factorModel();
    }
}
