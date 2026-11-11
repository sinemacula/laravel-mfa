<?php

declare(strict_types = 1);

namespace Tests\Integration;

use Illuminate\Foundation\Testing\RefreshDatabase;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Contracts\EloquentFactor;
use SineMacula\Laravel\Mfa\Exceptions\InvalidModelException;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\MfaManager;
use SineMacula\Laravel\Mfa\Models\Factor;
use Tests\Fixtures\Factors\CustomFactor;
use Tests\TestCase;

/**
 * `factorModel()` honours `mfa.factor.model` and refuses a misconfigured value
 * instead of falling back to the shipped model.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(MfaManager::class)]
final class CustomFactorModelTest extends TestCase
{
    use RefreshDatabase;

    /**
     * Resolving the manager validates the config, so do it while still valid.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        Mfa::getFacadeRoot();
    }

    /**
     * @return void
     */
    public function testReturnsShippedFactorModelByDefault(): void
    {
        // An unset env var or cleared key reads as null.
        config()->set('mfa.factor.model', null);

        self::assertSame(Factor::class, Mfa::factorModel());
    }

    /**
     * @return void
     */
    public function testReturnsConfiguredCustomFactorModel(): void
    {
        config()->set('mfa.factor.model', CustomFactor::class);

        self::assertSame(CustomFactor::class, Mfa::factorModel());
        self::assertSame(CustomFactor::FIXTURE_TAG, 'custom-factor-fixture');
    }

    /**
     * @return void
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
     * A non-string value must not reach `class_exists`, which only warns.
     *
     * @return void
     */
    public function testRejectsNonStringConfigValue(): void
    {
        config()->set('mfa.factor.model', 123);

        $this->expectException(InvalidModelException::class);
        $this->expectExceptionMessage('must be a class string');

        Mfa::factorModel();
    }

    /**
     * @return void
     */
    public function testRejectsEmptyStringConfigValue(): void
    {
        config()->set('mfa.factor.model', '');

        $this->expectException(InvalidModelException::class);
        $this->expectExceptionMessage('must be a class string');

        Mfa::factorModel();
    }

    /**
     * The message names the missing class.
     *
     * @return void
     */
    public function testRejectsNonExistentClass(): void
    {
        config()->set('mfa.factor.model', 'App\DoesNotExistFactor');

        $this->expectException(InvalidModelException::class);
        $this->expectExceptionMessage('App\DoesNotExistFactor');

        Mfa::factorModel();
    }

    /**
     * @return void
     */
    public function testRejectsClassThatDoesNotImplementEloquentFactor(): void
    {
        config()->set('mfa.factor.model', \stdClass::class);

        $this->expectException(InvalidModelException::class);
        $this->expectExceptionMessage('must extend');

        Mfa::factorModel();
    }
}
