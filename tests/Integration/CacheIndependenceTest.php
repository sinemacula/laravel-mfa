<?php

declare(strict_types = 1);

namespace Tests\Integration;

use Illuminate\Cache\ArrayStore;
use Illuminate\Cache\Repository;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\Cache;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Mfa\MfaManager;
use Tests\Fixtures\Hardening\Concerns\FlowCatalogue;
use Tests\TestCase;

/**
 * Nothing the package does asks the cache anything: every flow reaches its
 * branch with a cache store that throws on every call, and none is counted.
 * That also shows a cache that lies is irrelevant, as nothing reads it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(MfaManager::class)]
final class CacheIndependenceTest extends TestCase
{
    use FlowCatalogue;

    /** @var int How many calls reached the store. */
    private int $cacheCalls = 0;

    /**
     * Arrange the flows.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->arrangeVerification();
        $this->resetFlows();
    }

    /**
     * The flow reaches its branch without asking the cache anything.
     *
     * @param  string  $flow
     * @return void
     */
    #[DataProvider('flowNames')]
    public function testTheFlowNeverAsksTheCache(string $flow): void
    {
        $act = $this->flows()[$flow]();

        self::assertTrue($act(), 'The flow must reach its branch.');
        self::assertSame(0, $this->cacheCalls);
    }

    /**
     * The store does throw, so the flows above show something.
     *
     * @return void
     */
    public function testTheStoreIsDown(): void
    {
        try {
            Cache::get('anything');

            self::fail('The store must throw.');
        } catch (\RuntimeException $exception) {
            self::assertSame('The cache is down.', $exception->getMessage());
        }

        self::assertSame(1, $this->cacheCalls);
    }

    /**
     * The catalogue's names are the flows it holds.
     *
     * @return void
     */
    public function testTheCatalogueNamesEveryFlow(): void
    {
        self::assertSame(array_keys(self::flowNames()), array_keys($this->flows()));
    }

    /**
     * Point the default cache at a store that throws on every call.
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

        $store = \Mockery::mock(ArrayStore::class);

        $store->shouldReceive('get', 'many', 'put', 'putMany', 'increment', 'decrement', 'forever', 'forget', 'flush')->andReturnUsing(function (): never {

            $this->cacheCalls++;

            throw new \RuntimeException('The cache is down.');
        });

        $app->booting(static function () use ($store): void {
            Cache::extend('throwing', fn (): Repository => new Repository($store));
        });

        /** @var \Illuminate\Config\Repository $config */
        $config = $app->make(ConfigRepository::class);

        $config->set('cache.stores.throwing', ['driver' => 'throwing']);
        $config->set('cache.default', 'throwing');
    }
}
