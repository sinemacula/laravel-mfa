<?php

declare(strict_types = 1);

namespace Tests\Unit\Events;

use Illuminate\Config\Repository;
use Illuminate\Contracts\Container\Container;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Context\ClientContext;
use SineMacula\Laravel\Mfa\Contracts\EventContextResolver;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Events\EventDispatcher;
use SineMacula\Laravel\Mfa\Events\EventSubject;
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
     * array it returns by mistake is dropped, a key it does not know is `null`,
     * and the application is the operation's, never the resolver's.
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
            'application'    => 'admin',
            'session_id'     => null,
            'ip'             => null,
            'user_agent'     => null,
        ], $this->dispatcher()->context(new NonEloquentIdentity, 'admin'));
    }

    /**
     * The application an operation ran through names the application, over the
     * resolver's, and none named is none.
     *
     * @return void
     */
    public function testTheOperationsApplicationNamesTheApplication(): void
    {
        $this->bindResolver(['application' => 'web']);

        self::assertSame('admin', $this->dispatcher()->context(null, 'admin')['application']);
        self::assertNull($this->dispatcher()->context(null)['application']);
    }

    /**
     * The resolver is handed the subject: the identity, the application the
     * operation ran through, the sign-in it was bound to and the client it was
     * served to; with none of them given, a subject of which nothing is known
     * but an unknown client.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testTheResolverIsHandedTheSubject(): void
    {
        $identity = new NonEloquentIdentity;
        $client   = new ClientContext('192.0.2.1', 'agent');
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
             * @param  \SineMacula\Laravel\Mfa\Events\EventSubject  $subject
             * @return array<string, int|string|null>
             */
            #[\Override]
            public function resolve(EventSubject $subject): array
            {
                $this->seen->append($subject);

                return [];
            }
        });

        $this->dispatcher()->context($identity, 'web', $client, 'sign-in-1');
        $this->dispatcher()->context(null);

        self::assertEquals(new EventSubject($identity, 'web', 'sign-in-1', $client), $seen[0]);
        self::assertSame($client, $seen[0]->client);
        self::assertEquals(new EventSubject(null, null, null, ClientContext::unknown()), $seen[1]);
    }

    /**
     * Without a client, the context knows no address.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testWithoutAClientNoAddressIsKnown(): void
    {
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
             * @param  \SineMacula\Laravel\Mfa\Events\EventSubject  $subject
             * @return array<string, int|string|null>
             */
            #[\Override]
            public function resolve(EventSubject $subject): array
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
