<?php

declare(strict_types = 1);

namespace Tests\Unit\Database;

use Illuminate\Config\Repository;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\Config;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Database\StorageBindings;
use SineMacula\Laravel\Mfa\Exceptions\InvalidFactorModelException;
use SineMacula\Laravel\Mfa\Exceptions\ModelOffStorageConnectionException;
use SineMacula\Laravel\Mfa\MfaServiceProvider;
use Tests\Fixtures\Factors\SecondaryConnectionFactor;
use Tests\TestCase;

/**
 * The boot check that every configured model lives on the storage connection.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(StorageBindings::class)]
final class StorageBindingsTest extends TestCase
{
    /**
     * The shipped model follows the storage connection, wherever it is.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAcceptsTheShippedModel(): void
    {
        StorageBindings::boot($this->container());

        Config::set('mfa.storage.connection', 'secondary');

        StorageBindings::boot($this->container());

        $this->addToAssertionCount(2);
    }

    /**
     * A model naming the storage connection as its own is accepted.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAcceptsAModelOnTheConfiguredStorageConnection(): void
    {
        Config::set('mfa.storage.connection', 'secondary');
        Config::set('mfa.factor.model', SecondaryConnectionFactor::class);

        StorageBindings::boot($this->container());

        $this->addToAssertionCount(1);
    }

    /**
     * A configured model on another connection is refused when the package
     * boots, before it serves anything.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testTheProviderRefusesAModelOnAnotherConnectionAtBoot(): void
    {
        Config::set('mfa.factor.model', SecondaryConnectionFactor::class);

        $this->expectException(ModelOffStorageConnectionException::class);
        $this->expectExceptionMessage('the model is on [secondary], the package\'s tables on [testing]');

        (new MfaServiceProvider($this->container()))->boot();
    }

    /**
     * A configured model that is not a factor model fails at boot too, rather
     * than at a person's first change.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testRefusesAnInvalidModelAtBoot(): void
    {
        Config::set('mfa.factor.model', 'App\Missing');

        $this->expectException(InvalidFactorModelException::class);

        StorageBindings::boot($this->container());
    }

    /**
     * Register the `secondary` connection the tests name, so the migrations
     * rolled back when the application is destroyed find it.
     *
     * @param  mixed  $app
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        assert($app instanceof Application);

        $app->make(Repository::class)->set('database.connections.secondary', [
            'driver'   => 'sqlite',
            'database' => ':memory:',
            'prefix'   => '',
        ]);
    }
}
