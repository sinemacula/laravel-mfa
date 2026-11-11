<?php

declare(strict_types = 1);

namespace Tests\Unit\Proofs;

use Carbon\Carbon;
use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Context\CallerContext;
use SineMacula\Laravel\Mfa\Context\PendingContext;
use SineMacula\Laravel\Mfa\Contracts\PendingCompletion;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Contracts\RequirementCheck;
use SineMacula\Laravel\Mfa\Contracts\StepUp;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Enums\PendingAction;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException;
use SineMacula\Laravel\Mfa\Proofs\Proof;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
use SineMacula\Laravel\Mfa\Proofs\ProofStoreCompletion;
use SineMacula\Laravel\Mfa\Requirements\Requirement;
use SineMacula\Laravel\Mfa\Testing\Seams\Concerns\PendingCompletionTests;
use SineMacula\Laravel\Mfa\Testing\Seams\Concerns\StepUpTests;
use SineMacula\Laravel\Mfa\Verification\VerificationResult;
use Tests\Fixtures\Context\Callers;
use Tests\Fixtures\Identities\TestUser;
use Tests\Fixtures\Requirements\SignInProofs;
use Tests\TestCase;

/**
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ProofStoreCompletion::class)]
final class ProofStoreCompletionTest extends TestCase
{
    use PendingCompletionTests, StepUpTests;

    /** @var string The session the person's sign-in is named by. */
    private const string SESSION = 'sign-in-1';

    /** @var \Tests\Fixtures\Identities\TestUser The person signed in. */
    private TestUser $user;

    /**
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        Carbon::setTestNow('2026-11-01 12:00:00');

        $this->user = new TestUser(['email' => 'person@example.test']);

        $this->user->setAttribute('id', 7);

        $this->actingAs($this->user);

        $this->store()->begin($this->user, 'web', self::SESSION);
    }

    /**
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Carbon::setTestNow();

        parent::tearDown();
    }

    /**
     * @return void
     */
    public function testIsTheDefaultOfBothSeams(): void
    {
        self::assertInstanceOf(ProofStoreCompletion::class, $this->container()->make(PendingCompletion::class));
        self::assertInstanceOf(ProofStoreCompletion::class, $this->container()->make(StepUp::class));
    }

    /**
     * So is a sign-in completed alone on an active session; neither returns
     * anything.
     *
     * @return void
     */
    public function testAStepUpIsRecorded(): void
    {
        $seam  = $this->stepUp();
        $proof = $this->proof(Purpose::STEP_UP);

        self::assertNull($seam->stepUp(Callers::current(), $this->resultOf($proof)));
        self::assertSame([$proof->toArray()], $this->storedArrays());

        $signIn = $this->proof(Purpose::SIGN_IN);

        self::assertNull($seam->stepUp(Callers::current(), $this->resultOf($signIn)));
        self::assertSame([$proof->toArray(), $signIn->toArray()], $this->storedArrays());
    }

    /**
     * When the store's sign-in is the pending session's own.
     *
     * @return void
     */
    public function testAPendingCompletionIsRecorded(): void
    {
        $this->store()->begin($this->user, 'web', 'pending-1');

        $proof = $this->proof(Purpose::SIGN_IN, 'pending-1');

        self::assertNull($this->pendingCompletion()->complete(CallerContext::forPending($this->pendingContext()), $this->resultOf($proof)));
        self::assertSame([$proof->toArray()], $this->storedArrays('pending-1'));
    }

    /**
     * Never when the transaction rolls back.
     *
     * @return void
     */
    public function testTheStoreIsWrittenAfterTheCommit(): void
    {
        $seam  = $this->stepUp();
        $proof = $this->proof(Purpose::STEP_UP);

        DB::beginTransaction();
        $seam->stepUp(Callers::current(), $this->resultOf($proof));

        $during = $this->store()->proofs($this->user, 'web', self::SESSION);

        DB::rollBack();

        $rolledBack = $this->store()->proofs($this->user, 'web', self::SESSION);

        DB::beginTransaction();
        $seam->stepUp(Callers::current(), $this->resultOf($proof));
        DB::commit();

        self::assertSame([], $during);
        self::assertSame([], $rolledBack);
        self::assertCount(1, $this->store()->proofs($this->user, 'web', self::SESSION));
    }

    /**
     * Without a person signed in, or for a purpose an active session cannot
     * take.
     *
     * @return void
     */
    public function testAStepUpIsRefusedWhatAnActiveSessionCannotTake(): void
    {
        $this->assertNotAccepted(fn () => $this->stepUp()->stepUp(Callers::current(), $this->resultOf($this->proof(Purpose::ENROLLMENT))));
        $this->assertNotAccepted(fn () => $this->stepUp()->stepUp(Callers::current(), $this->resultOf($this->proof(Purpose::REAUTHENTICATE))));

        $this->assertNotAccepted(function (): void {
            $other = new TestUser;

            $other->setAttribute('id', 8);

            $binding = new ProofBinding($other->getMorphClass(), '8', 'web', self::SESSION, Purpose::STEP_UP);
            $proof   = self::rebound(SignInProofs::of($other)->inSession(self::SESSION)->totp(), $binding);

            $this->stepUp()->stepUp(Callers::current(), $this->resultOf($proof));
        });

        $this->store()->forget($this->user, 'web');

        $this->assertNotAccepted(fn () => $this->stepUp()->stepUp(Callers::current(), $this->resultOf($this->proof(Purpose::STEP_UP))));

        $this->app?->make('auth')->forgetGuards();

        $this->assertNotAccepted(fn () => $this->stepUp()->stepUp(Callers::current(), $this->resultOf($this->proof(Purpose::STEP_UP))));
    }

    /**
     * Another purpose than sign-in, another application or owner, and, when the
     * store is on another sign-in, the proof bound to the pending id.
     *
     * @return void
     */
    public function testAPendingCompletionRefusesAnotherBinding(): void
    {
        $pending = $this->pendingContext();

        $this->store()->begin($this->user, 'web', 'pending-1');

        $this->assertNotAccepted(fn () => $this->pendingCompletion()->complete(CallerContext::forPending($pending), $this->resultOf($this->proof(Purpose::STEP_UP, 'pending-1'))));
        $this->assertNotAccepted(fn () => $this->pendingCompletion()->complete(CallerContext::forPending($pending), $this->resultOf($this->proof(Purpose::SIGN_IN, 'another'))));

        $this->store()->begin($this->user, 'web', 'another');

        $this->assertNotAccepted(fn () => $this->pendingCompletion()->complete(CallerContext::forPending($pending), $this->resultOf($this->proof(Purpose::SIGN_IN, 'pending-1'))));
    }

    /**
     * Even with a proof the pending session would take; nothing is recorded.
     *
     * @return void
     */
    public function testAPendingCompletionRefusesACallerWithNoPendingSession(): void
    {
        $this->store()->begin($this->user, 'web', 'pending-1');

        $active = CallerContext::forIdentity($this->user, 'web');

        $this->assertNotAccepted(fn () => $this->pendingCompletion()->complete($active, $this->resultOf($this->proof(Purpose::SIGN_IN, 'pending-1'))));

        self::assertSame([], $this->storedArrays('pending-1'));
    }

    /**
     * @return \SineMacula\Laravel\Mfa\Contracts\PendingCompletion
     */
    #[\Override]
    protected function pendingCompletion(): PendingCompletion
    {
        return $this->container()->make(ProofStoreCompletion::class);
    }

    /**
     * @return \SineMacula\Laravel\Mfa\Context\PendingContext
     */
    #[\Override]
    protected function pendingContext(): PendingContext
    {
        return new PendingContext(
            $this->user,
            'web',
            'pending-1',
            SignInProofs::of($this->user)->inSession('pending-1')->password(),
            Requirement::none(),
            [PendingAction::VERIFY],
            CarbonImmutable::now()->addHour(),
        );
    }

    /**
     * @return \SineMacula\Laravel\Mfa\Verification\VerificationResult
     */
    #[\Override]
    protected function resultOfThePendingSession(): VerificationResult
    {
        $this->store()->begin($this->user, 'web', 'pending-1');

        return $this->resultOf($this->proof(Purpose::SIGN_IN, 'pending-1'));
    }

    /**
     * @return \SineMacula\Laravel\Mfa\Verification\VerificationResult
     */
    #[\Override]
    protected function resultOfAnotherBinding(): VerificationResult
    {
        return $this->resultOf($this->proof(Purpose::SIGN_IN, 'another-session'));
    }

    /**
     * @return \SineMacula\Laravel\Mfa\Contracts\StepUp
     */
    #[\Override]
    protected function stepUp(): StepUp
    {
        return $this->container()->make(ProofStoreCompletion::class);
    }

    /**
     * @return \SineMacula\Laravel\Mfa\Verification\VerificationResult
     */
    #[\Override]
    protected function stepUpResultOfAnotherBinding(): VerificationResult
    {
        return $this->resultOf($this->proof(Purpose::STEP_UP, 'another-session'));
    }

    /**
     * @return \SineMacula\Laravel\Mfa\Context\CallerContext
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[\Override]
    protected function stepUpCaller(): CallerContext
    {
        return Callers::current();
    }

    /**
     * @param  \Closure(): mixed  $call
     * @return void
     */
    private function assertNotAccepted(\Closure $call): void
    {
        try {
            $call();
        } catch (OperationRefusedException $exception) {
            self::assertSame(FailureReason::NOT_ACCEPTED, $exception->reason);

            return;
        }

        self::fail('The call was expected to be refused.');
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Enums\Purpose  $purpose
     * @param  string  $session
     * @return \SineMacula\Laravel\Mfa\Proofs\Proof
     */
    private function proof(Purpose $purpose, string $session = self::SESSION): Proof
    {
        $binding = new ProofBinding($this->user->getMorphClass(), '7', 'web', $session, $purpose);

        return self::rebound(SignInProofs::of($this->user)->inSession($session)->totp(), $binding);
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Proofs\Proof  $proof
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @return \SineMacula\Laravel\Mfa\Proofs\Proof
     */
    private static function rebound(Proof $proof, ProofBinding $binding): Proof
    {
        return new Proof($proof->kind, $proof->method, $proof->channel, $proof->reference, $proof->properties, $proof->provedAt, $binding, $proof->generation, $proof->challengeId);
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Proofs\Proof  $proof
     * @return \SineMacula\Laravel\Mfa\Verification\VerificationResult
     */
    private function resultOf(Proof $proof): VerificationResult
    {
        return VerificationResult::verified($proof, $this->container()->make(RequirementCheck::class)->check(Requirement::none(), $proof), ['otp'], 'totp');
    }

    /**
     * @param  string  $session
     * @return list<array<string, mixed>>
     */
    private function storedArrays(string $session = self::SESSION): array
    {
        return array_map(static fn (Proof $proof): array => $proof->toArray(), $this->store()->proofs($this->user, 'web', $session));
    }

    /**
     * @return \SineMacula\Laravel\Mfa\Contracts\ProofStore
     */
    private function store(): ProofStore
    {
        return $this->container()->make(ProofStore::class);
    }
}
