<?php

declare(strict_types = 1);

namespace Tests\Unit\Database;

use Illuminate\Config\Repository;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Facade;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Mfa\Database\StorageConnection;
use SineMacula\Laravel\Mfa\Exceptions\ModelOffStorageConnectionException;
use SineMacula\Laravel\Mfa\Models\Factor;
use Tests\Fixtures\Factors\SecondaryConnectionFactor;
use Tests\TestCase;

/**
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(StorageConnection::class)]
final class StorageConnectionTest extends TestCase
{
    /**
     * @return void
     */
    public function testNamesNoConnectionWhenTheSettingIsUnsetOrEmpty(): void
    {
        Config::set('mfa.storage.connection', null);

        self::assertNull(StorageConnection::name());
        self::assertSame('testing', StorageConnection::resolvedName());

        Config::set('mfa.storage.connection', '');

        self::assertNull(StorageConnection::name());
        self::assertSame('testing', StorageConnection::resolvedName());
    }

    /**
     * @return void
     */
    public function testNamesTheConfiguredConnection(): void
    {
        Config::set('mfa.storage.connection', 'secondary');

        self::assertSame('secondary', StorageConnection::name());
        self::assertSame('secondary', StorageConnection::resolvedName());
    }

    /**
     * Settings that are neither a name nor empty.
     *
     * @return iterable<string, array{mixed}>
     */
    public static function malformedSettings(): iterable
    {
        yield 'integer' => [42];
        yield 'list' => [['secondary']];
        yield 'boolean' => [true];
    }

    /**
     * @param  mixed  $setting
     * @return void
     */
    #[DataProvider('malformedSettings')]
    public function testRefusesAMalformedSetting(mixed $setting): void
    {
        Config::set('mfa.storage.connection', $setting);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('`mfa.storage.connection` must be a connection name, or null or empty for the default connection.');

        try {
            StorageConnection::name();
        } finally {
            Config::set('mfa.storage.connection', null);
        }
    }

    /**
     * Before the configuration is bootstrapped, it is built on the default
     * connection.
     *
     * @return void
     */
    public function testAShippedModelIsBuiltOnTheStorageConnectionByName(): void
    {
        self::assertSame('testing', StorageConnection::forModel());

        Config::set('mfa.storage.connection', 'secondary');

        try {
            self::assertSame('secondary', StorageConnection::forModel());
        } finally {
            Config::set('mfa.storage.connection', null);
        }

        $previous = Facade::getFacadeApplication();

        // @phpstan-ignore argument.type
        Facade::setFacadeApplication(null);
        Facade::clearResolvedInstance('config');

        try {
            self::assertNull(StorageConnection::forModel());
        } finally {
            Facade::setFacadeApplication($previous);
        }
    }

    /**
     * @return void
     */
    public function testNamesAModelsConnection(): void
    {
        self::assertSame('testing', StorageConnection::nameOf(new Factor));
        self::assertSame('secondary', StorageConnection::nameOf(new SecondaryConnectionFactor));
    }

    /**
     * @return void
     */
    public function testAcceptsAModelOnTheStorageConnection(): void
    {
        StorageConnection::assertHolds(new Factor, 'mfa.factor.model');

        Config::set('mfa.storage.connection', 'secondary');

        StorageConnection::assertHolds(new SecondaryConnectionFactor, 'mfa.factor.model');
        StorageConnection::assertHolds(new Factor, 'mfa.factor.model');

        $this->addToAssertionCount(3);
    }

    /**
     * @return void
     */
    public function testRefusesAModelOnAnotherConnection(): void
    {
        $this->expectException(ModelOffStorageConnectionException::class);
        $this->expectExceptionMessage(sprintf(
            'mfa.factor.model class [%s] must be on the storage connection (`mfa.storage.connection`): the model is on [secondary], the package\'s tables on [testing].',
            SecondaryConnectionFactor::class,
        ));

        StorageConnection::assertHolds(new SecondaryConnectionFactor, 'mfa.factor.model');
    }

    /**
     * The migrations rolled back on teardown need the `secondary` connection.
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
