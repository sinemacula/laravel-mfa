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
use Tests\Fixtures\Context\Callers;
use Tests\Fixtures\Hardening\Concerns\FlowCatalog;
use Tests\Fixtures\Hardening\LockOrderRecorder;
use Tests\Fixtures\Hardening\SpyCompletion;
use Tests\Fixtures\Hardening\SpySessionRevoker;
use Tests\Fixtures\Hardening\SpySessionTransition;
use Tests\Fixtures\Identities\TestUser;
use Tests\TestCase;

/**
 * Every flow locks the identity's row first, one owner's only, and no package
 * row after a session seam; contention is left to the server-database tests.
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

    /** @var \Tests\Fixtures\Hardening\LockOrderRecorder Statement and seam log. */
    private LockOrderRecorder $recorder;

    /**
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
     * @param  string  $flow
     * @return void
     */
    #[DataProvider('flowNames')]
    public function testTheFlowKeepsTheLockOrder(string $flow): void
    {
        $this->assertFlowKeepsTheLockOrder($flow);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function revokingFlows(): iterable
    {
        foreach (['remove factor', 'remove last factor', 'reset identity', 'passkey removing'] as $flow) {
            yield $flow => [$flow];
        }
    }

    /**
     * The default revoker's generation bump is the seam's own write.
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
     * The control: the recorder sees what the sweep relies on.
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
     * @return void
     */
    public function testListenersOnRemovalEventsFindTheKeptProofs(): void
    {
        $this->container()->instance(SessionRevoker::class, $this->container()->make(GenerationSessionRevoker::class));

        $act  = $this->flows()['remove last factor']();
        $seen = [];

        foreach ([FactorRemoved::class, RecoveryCodesRemoved::class] as $event) {
            Event::listen($event, function (object $removed) use (&$seen): void {
                $seen[class_basename($removed)] = array_map(static fn (Proof $proof): string => $proof->method, Mfa::proofs(Callers::current()));
            });
        }

        self::assertTrue($act());

        self::assertSame(['FactorRemoved', 'RecoveryCodesRemoved'], array_keys($seen));

        foreach ($seen as $methods) {
            self::assertContains('password', $methods);
        }
    }

    /**
     * Whatever the revoker locks comes after every package row has changed.
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
     * Someone else's credential is never returned or acted on.
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
     * @return \Tests\Fixtures\Identities\TestUser
     */
    private function sole(): TestUser
    {
        return TestUser::query()->sole();
    }

    /**
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
