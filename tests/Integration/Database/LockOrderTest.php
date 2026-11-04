<?php

declare(strict_types = 1);

namespace Tests\Integration\Database;

use Illuminate\Database\Connection;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Mfa\Contracts\PendingCompletion;
use SineMacula\Laravel\Mfa\Contracts\SessionRevoker;
use SineMacula\Laravel\Mfa\Contracts\SessionTransition;
use SineMacula\Laravel\Mfa\Contracts\StepUp;
use SineMacula\Laravel\Mfa\Database\IdentityStateRow;
use SineMacula\Laravel\Mfa\Database\StorageConnection;
use SineMacula\Laravel\Mfa\Database\TableNames;
use SineMacula\Laravel\Mfa\Enrollment\PendingEnrollments;
use SineMacula\Laravel\Mfa\Events\FactorRemoved;
use SineMacula\Laravel\Mfa\Events\RecoveryCodesRemoved;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\Lifecycle\FactorRemoval;
use SineMacula\Laravel\Mfa\Models\RecoveryCode;
use SineMacula\Laravel\Mfa\Passkeys\PasskeyAssociations;
use SineMacula\Laravel\Mfa\Passkeys\PasskeyChangeGate;
use SineMacula\Laravel\Mfa\Proofs\GenerationSessionRevoker;
use SineMacula\Laravel\Mfa\Proofs\Proof;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;
use SineMacula\Laravel\Mfa\Proofs\ProofStoreCompletion;
use SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeService;
use Tests\Fixtures\Hardening\Concerns\FlowCatalog;
use Tests\Fixtures\Hardening\LockOrderRecorder;
use Tests\Fixtures\Hardening\SpyCompletion;
use Tests\Fixtures\Hardening\SpySessionRevoker;
use Tests\Fixtures\Hardening\SpySessionTransition;
use Tests\Fixtures\Identities\TestUser;
use Tests\TestCase;

/**
 * The lock order every flow shares, read from its statements on the storage
 * connection and its calls to the session seams, in one log: the identity's row
 * first, one owner's only, and nothing of the package's after a session seam,
 * so a package row is never locked after a session row.
 *
 * This is evidence of the order of the statements. Whether two changes contend
 * is left to the tests run on MySQL and PostgreSQL: SQLite cannot show the
 * absence of a gap or next-key deadlock.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FactorRemoval::class)]
#[CoversClass(RecoveryCodeService::class)]
#[CoversClass(PendingEnrollments::class)]
#[CoversClass(PasskeyAssociations::class)]
#[CoversClass(PasskeyChangeGate::class)]
#[CoversClass(IdentityStateRow::class)]
final class LockOrderTest extends TestCase
{
    use FlowCatalog;

    /** @var \Tests\Fixtures\Hardening\LockOrderRecorder The log of the flow. */
    private LockOrderRecorder $recorder;

    /**
     * Arrange the flows, record the storage connection, and put a spy in place
     * of each session seam.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->arrangeVerification();
        $this->resetFlows();

        $connection = DB::connection(StorageConnection::name());

        self::assertInstanceOf(Connection::class, $connection);

        $this->recorder = new LockOrderRecorder($connection);

        $completion = new SpyCompletion($this->recorder, $this->container()->make(ProofStoreCompletion::class));

        $this->container()->instance(SessionRevoker::class, new SpySessionRevoker($this->recorder));
        $this->container()->instance(SessionTransition::class, new SpySessionTransition($this->recorder));
        $this->container()->instance(PendingCompletion::class, $completion);
        $this->container()->instance(StepUp::class, $completion);
    }

    /**
     * The flow keeps the lock order.
     *
     * @param  string  $flow
     * @return void
     */
    #[DataProvider('flowNames')]
    public function testTheFlowKeepsTheLockOrder(string $flow): void
    {
        $this->assertFlowKeepsTheLockOrder($flow);
    }

    /**
     * Rows of a flow that revokes the identity's sessions.
     *
     * @return iterable<string, array{string}>
     */
    public static function revokingFlows(): iterable
    {
        foreach (['remove factor', 'remove last factor', 'reset identity', 'passkey removing'] as $flow) {
            yield $flow => [$flow];
        }
    }

    /**
     * The default revoker's own advance of the generation is the seam's work on
     * the owner's own row; nothing orchestrating it writes after it.
     *
     * @param  string  $flow
     * @return void
     */
    #[DataProvider('revokingFlows')]
    public function testNothingIsWrittenAfterTheDefaultRevokerFinishes(string $flow): void
    {
        $this->container()->instance(SessionRevoker::class, new SpySessionRevoker($this->recorder, $this->container()->make(GenerationSessionRevoker::class)));

        $this->assertFlowKeepsTheLockOrder($flow);

        self::assertNotSame([], $this->recorder->seams());
    }

    /**
     * The recorder sees what it must, or the sweep above shows nothing: a
     * removal locks the owner's row first, calls the seams, and its recovery
     * codes are gone before the first of them.
     *
     * @return void
     */
    public function testALastFactorsRemovalIsRecordedInOrder(): void
    {
        $act = $this->flows()['remove last factor']();

        $this->recorder->start();

        self::assertTrue($act());
        self::assertSame(['factorRemoved', 'factorChanged'], $this->recorder->seams());

        $seen = [];

        foreach ($this->recorder->log as $entry) {

            if (isset($entry['statement']) && !str_contains($entry['statement'], TableNames::of(TableNames::RECOVERY_CODES))) {
                continue;
            }

            $seen[] = $entry['statement'] ?? 'seam';
        }

        self::assertCount(3, $seen);
        self::assertStringContainsString('delete', $seen[0]);
        self::assertSame(['seam', 'seam'], array_slice($seen, 1));
    }

    /**
     * A listener on each removal event finds the proofs the session kept, on
     * the default revoker, in the order the events have always had.
     *
     * @return void
     */
    public function testListenersOnRemovalEventsFindTheKeptProofs(): void
    {
        $this->container()->instance(SessionRevoker::class, $this->container()->make(GenerationSessionRevoker::class));

        $act  = $this->flows()['remove last factor']();
        $seen = [];

        foreach ([FactorRemoved::class, RecoveryCodesRemoved::class] as $event) {
            Event::listen($event, function (object $removed) use (&$seen): void {
                $seen[class_basename($removed)] = array_map(static fn (Proof $proof): string => $proof->method, Mfa::proofs());
            });
        }

        self::assertTrue($act());

        self::assertSame(['FactorRemoved', 'RecoveryCodesRemoved'], array_keys($seen));

        foreach ($seen as $methods) {
            self::assertContains('password', $methods);
        }
    }

    /**
     * A revoker sees no recovery code when it is called, so what it locks comes
     * after every package row has changed.
     *
     * @return void
     */
    public function testARevokerSeesNoRecoveryCode(): void
    {
        $remaining = null;

        $this->container()->instance(SessionRevoker::class, new SpySessionRevoker($this->recorder, null, static function () use (&$remaining): void {
            $remaining = RecoveryCode::query()->count();
        }));

        $act = $this->flows()['remove last factor']();

        self::assertGreaterThan(0, RecoveryCode::query()->count());
        self::assertTrue($act());
        self::assertSame(0, $remaining);
    }

    /**
     * A grant is looked up, locked, within its owner's rows.
     *
     * @return void
     */
    public function testTheGrantsLockingLookupNamesItsOwner(): void
    {
        $act = $this->flows()['enrollment confirm']();

        $this->recorder->start();

        self::assertTrue($act());

        $owner  = ProofOwner::of($this->sole());
        $lookup = $this->lookupsBy('grant_hash', TableNames::of(TableNames::ENROLLMENTS));

        self::assertNotSame([], $lookup);

        foreach ($lookup as $bindings) {
            self::assertContains($owner->type, $bindings);
            self::assertContains($owner->key, $bindings);
        }
    }

    /**
     * The lookup that locks a credential names who is removing it, so someone
     * else's is never returned or acted on, and is refused all the same.
     *
     * @return void
     */
    public function testTheCredentialsLockingLookupNamesItsOwner(): void
    {
        $act = $this->flows()['passkey removing foreign']();

        $owner = ProofOwner::of(TestUser::query()->where('email', self::ADDRESS)->sole());

        $this->recorder->start();

        self::assertTrue($act());

        $lookup = $this->lookupsBy('credential_id_hash', TableNames::of(TableNames::PASSKEY_ASSOCIATIONS));

        self::assertNotSame([], $lookup);

        foreach ($lookup as $bindings) {
            self::assertContains($owner->key, $bindings);
        }
    }

    /**
     * The only person seeded.
     *
     * @return \Tests\Fixtures\Identities\TestUser
     */
    private function sole(): TestUser
    {
        return TestUser::query()->sole();
    }

    /**
     * The bindings of each locking read of the table by the column.
     *
     * @param  string  $column
     * @param  string  $table
     * @return list<array<int|string, mixed>>
     */
    private function lookupsBy(string $column, string $table): array
    {
        $found = [];

        foreach ($this->recorder->lockingOrWriting($table) as $entry) {

            if (!str_contains($entry['statement'], $column) || stripos($entry['statement'], 'for update') === false) {
                continue;
            }

            $found[] = $entry['bindings'];
        }

        return $found;
    }

    /**
     * Seed the flow, run it and assert its log keeps the lock order.
     *
     * @param  string  $flow
     * @return void
     */
    private function assertFlowKeepsTheLockOrder(string $flow): void
    {
        $act = $this->flows()[$flow]();

        $this->recorder->start();

        self::assertTrue($act(), 'The flow must reach its branch.');
        self::assertSame([], $this->recorder->violations());
    }
}
