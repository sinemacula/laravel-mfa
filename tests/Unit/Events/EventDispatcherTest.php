<?php

declare(strict_types = 1);

namespace Tests\Unit\Events;

use Illuminate\Config\Repository;
use Illuminate\Contracts\Container\Container;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Contracts\EventContextResolver;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Events\EventDispatcher;
use SineMacula\Laravel\Mfa\Events\RecoveryCodeUsed;
use Tests\Fixtures\Identities\NonEloquentIdentity;
use Tests\TestCase;

/**
 * Unit tests for `EventDispatcher`: events reach listeners only once the change
 * they report commits on the storage connection, never after a rollback, and
 * each carries the allowlisted context of the bound resolver.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(EventDispatcher::class)]
final class EventDispatcherTest extends TestCase
{
    use RefreshDatabase;

    /**
     * With no transaction open, the event is dispatched at once.
     *
     * @return void
     */
    public function testDispatchesAtOnceOutsideATransaction(): void
    {
        Event::fake([RecoveryCodeUsed::class]);

        $this->dispatcher()->dispatch(new RecoveryCodeUsed([], 4, Purpose::SIGN_IN));

        Event::assertDispatched(RecoveryCodeUsed::class, static fn (RecoveryCodeUsed $event): bool => $event->remaining === 4);
    }

    /**
     * Inside a transaction on the storage connection, the event waits for the
     * commit.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testWaitsForTheStorageConnectionToCommit(): void
    {
        Event::fake([RecoveryCodeUsed::class]);

        DB::connection()->transaction(function (): void {

            $this->dispatcher()->dispatch(new RecoveryCodeUsed([], 4, Purpose::SIGN_IN));

            Event::assertNotDispatched(RecoveryCodeUsed::class);
        });

        Event::assertDispatchedTimes(RecoveryCodeUsed::class, 1);
    }

    /**
     * A rollback dispatches nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARollbackDispatchesNothing(): void
    {
        Event::fake([RecoveryCodeUsed::class]);

        try {
            DB::connection()->transaction(function (): void {

                $this->dispatcher()->dispatch(new RecoveryCodeUsed([], 4, Purpose::SIGN_IN));

                throw new \RuntimeException('The change failed.');
            });
        } catch (\RuntimeException) {
            // The change rolled back.
        }

        Event::assertNotDispatched(RecoveryCodeUsed::class);
    }

    /**
     * A transaction open on another connection neither delays nor drops the
     * event, since the package's changes are not made in it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATransactionOnAnotherConnectionDoesNotDelayTheEvent(): void
    {
        Event::fake([RecoveryCodeUsed::class]);

        $this->container()->make(Repository::class)->set('database.connections.secondary', ['driver' => 'sqlite', 'database' => ':memory:', 'prefix' => '']);

        try {
            DB::connection('secondary')->transaction(function (): void {

                $this->dispatcher()->dispatch(new RecoveryCodeUsed([], 4, Purpose::SIGN_IN));

                Event::assertDispatchedTimes(RecoveryCodeUsed::class, 1);

                throw new \RuntimeException('The other change failed.');
            });
        } catch (\RuntimeException) {
            // Only the other connection's change rolled back.
        }

        Event::assertDispatchedTimes(RecoveryCodeUsed::class, 1);
    }

    /**
     * Without a transactions manager, the event is dispatched at once.
     *
     * @return void
     */
    public function testDispatchesAtOnceWithoutATransactionsManager(): void
    {
        Event::fake([RecoveryCodeUsed::class]);

        $this->container()->forgetInstance('db.transactions');
        $this->container()->offsetUnset('db.transactions');

        $this->dispatcher()->dispatch(new RecoveryCodeUsed([], 4, Purpose::SIGN_IN));

        Event::assertDispatchedTimes(RecoveryCodeUsed::class, 1);
    }

    /**
     * The context is the resolver's, cut down to the allowlist: a model or an
     * array it returns by mistake is dropped, and a key it does not know is
     * `null`.
     *
     * @return void
     */
    public function testTheContextIsTheResolversCutDownToTheAllowlist(): void
    {
        $this->bindResolver([
            'identity_type' => 'person',
            'identity_id'   => 7,
            'principal_id'  => new class extends Model {},
            'tenant_id'     => ['t1'],
            'application'   => 'web',
            'password'      => 'secret',
        ]);

        self::assertSame([
            'identity_type'  => 'person',
            'identity_id'    => 7,
            'principal_type' => null,
            'principal_id'   => null,
            'tenant_id'      => null,
            'application'    => 'web',
            'session_id'     => null,
            'ip'             => null,
            'user_agent'     => null,
        ], $this->dispatcher()->context(new NonEloquentIdentity));
    }

    /**
     * The application an operation ran through names the application, over the
     * resolver's.
     *
     * @return void
     */
    public function testTheOperationsApplicationNamesTheApplication(): void
    {
        $this->bindResolver(['application' => 'web']);

        self::assertSame('admin', $this->dispatcher()->context(null, 'admin')['application']);
        self::assertSame('web', $this->dispatcher()->context(null)['application']);
    }

    /**
     * The resolver is handed the identity and the request being served.
     *
     * @return void
     */
    public function testTheResolverIsHandedTheIdentityAndTheRequest(): void
    {
        $identity = new NonEloquentIdentity;
        /** @var \ArrayObject<int, mixed> $seen */
        $seen = new \ArrayObject;

        $this->container()->instance(EventContextResolver::class, new class ($seen) implements EventContextResolver {
            /**
             * Constructor.
             *
             * @param  \ArrayObject<int, mixed>  $seen
             */
            public function __construct(

                /** What the resolver was handed. */
                private readonly \ArrayObject $seen,
            ) {}

            /**
             * Record what the resolver was handed.
             *
             * @param  ?\SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
             * @param  ?\Illuminate\Http\Request  $request
             * @return array<string, int|string|null>
             */
            #[\Override]
            public function resolve(?MultiFactorAuthenticatable $identity, ?Request $request): array
            {
                $this->seen->append($identity);
                $this->seen->append($request);

                return [];
            }
        });

        $this->dispatcher()->context($identity);

        self::assertSame($identity, $seen[0]);
        self::assertSame($this->container()->make('request'), $seen[1]);
    }

    /**
     * Without a request bound, the resolver is handed none.
     *
     * @return void
     */
    public function testWithoutARequestTheResolverIsHandedNone(): void
    {
        $this->container()->forgetInstance('request');
        $this->container()->offsetUnset('request');

        $context = $this->dispatcher()->context(new NonEloquentIdentity);

        self::assertSame('plain-1', $context['identity_id']);
        self::assertNull($context['ip']);
    }

    /**
     * Bind a resolver that answers the given values.
     *
     * @param  array<string, mixed>  $values
     * @return void
     */
    private function bindResolver(array $values): void
    {
        $this->container()->instance(EventContextResolver::class, new class ($values) implements EventContextResolver {
            /**
             * Constructor.
             *
             * @param  array<string, mixed>  $values
             */
            public function __construct(

                /** What the resolver answers. */
                private readonly array $values,
            ) {}

            /**
             * Answer the values, whatever they are.
             *
             * @param  ?\SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
             * @param  ?\Illuminate\Http\Request  $request
             * @return array<string, int|string|null>
             */
            #[\Override]
            public function resolve(?MultiFactorAuthenticatable $identity, ?Request $request): array
            {
                /** @var array<string, int|string|null> */
                return $this->values;
            }
        });
    }

    /**
     * Resolve the dispatcher.
     *
     * @return \SineMacula\Laravel\Mfa\Events\EventDispatcher
     */
    private function dispatcher(): EventDispatcher
    {
        return new EventDispatcher($this->container()->make(Container::class));
    }
}
