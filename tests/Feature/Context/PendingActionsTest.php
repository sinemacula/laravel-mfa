<?php

declare(strict_types = 1);

namespace Tests\Feature\Context;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Context\CallerContextResolver;
use SineMacula\Laravel\Mfa\Context\PendingContext;
use SineMacula\Laravel\Mfa\Contracts\PendingSessionResolver;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Enums\PendingAction;
use SineMacula\Laravel\Mfa\Factors\FactorService;
use SineMacula\Laravel\Mfa\Factors\FactorSummary;
use SineMacula\Laravel\Mfa\Lifecycle\LifecycleService;
use SineMacula\Laravel\Mfa\MfaManager;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Models\RecoveryCode;
use SineMacula\Laravel\Mfa\Proofs\ProofService;
use SineMacula\Laravel\Mfa\Requirements\Requirement;
use SineMacula\Laravel\Mfa\Testing\FakeEmailSender;
use SineMacula\Laravel\Mfa\Verification\Submission;
use SineMacula\Laravel\Mfa\Verification\VerificationService;
use Tests\Fixtures\Context\Callers;
use Tests\Fixtures\Context\FixedPendingSessionResolver;
use Tests\Fixtures\Context\RecordingPendingSessionResolver;
use Tests\Fixtures\Exceptions\InvalidPendingCredentialException;
use Tests\Fixtures\Identities\TestUser;
use Tests\Fixtures\Requirements\SignInProofs;
use Tests\TestCase;

/**
 * A pending session gets only the actions it allows, as its own identity and
 * never as the guard's user.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CallerContextResolver::class)]
#[CoversClass(FactorService::class)]
#[CoversClass(VerificationService::class)]
#[CoversClass(MfaManager::class)]
#[CoversClass(ProofService::class)]
#[CoversClass(LifecycleService::class)]
final class PendingActionsTest extends TestCase
{
    /** @var \Tests\Fixtures\Identities\TestUser Person signing in on the pending session. */
    private TestUser $pending;

    /** @var \SineMacula\Laravel\Mfa\Models\Factor Pending person's email factor. */
    private Factor $factor;

    /** @var \SineMacula\Laravel\Mfa\Models\Factor Guard's user's email factor. */
    private Factor $guardedFactor;

    /** @var \SineMacula\Laravel\Mfa\Testing\FakeEmailSender The codes sent. */
    private FakeEmailSender $mailbox;

    /**
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        config()->set('hashing.bcrypt.rounds', 4);
        config()->set('mfa.applications.web', [
            'types'          => ['email'],
            'recovery_codes' => ['enabled' => true],
            'first_factor'   => ['method' => 'password', 'channel' => 'password'],
        ]);

        $this->mailbox = FakeEmailSender::fake($this->container());

        /** @var \Tests\Fixtures\Identities\TestUser $guarded */
        $guarded = TestUser::query()->create(['email' => 'guarded@example.test']);

        /** @var \Tests\Fixtures\Identities\TestUser $pending */
        $pending = TestUser::query()->create(['email' => 'pending@example.test']);

        $this->pending = $pending;
        $this->factor  = $this->emailFactor($pending, 'pending@example.test');

        $this->guardedFactor = $this->emailFactor($guarded, 'guarded@example.test');
        $this->actingAs($guarded);

        $this->container()->make(ProofStore::class)->begin($guarded, 'web', SignInProofs::SESSION);
        $this->container()->make(ProofStore::class)->record($guarded, SignInProofs::of($guarded)->password());
    }

    /**
     * The guard's user is not served in the pending person's place.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPendingSessionWithoutTheActionGetsNothing(): void
    {
        $this->pendingSession([PendingAction::START_BOOTSTRAP_ENROLLMENT]);

        self::assertSame([], $this->manager()->factors(Callers::current()));
        self::assertNull($this->manager()->factor(Callers::current(), $this->factor->id));
        self::assertSame(FailureReason::NOT_FOUND, $this->manager()->sendCode(Callers::current(), $this->factor->id)->reason);
        self::assertSame(FailureReason::NOT_FOUND, $this->manager()->verify(Callers::current(), Submission::challenge($this->factor->id, 'any', '123456'))->reason);
        self::assertSame(FailureReason::NOT_FOUND, $this->manager()->verify(Callers::current(), Submission::recoveryCode('ABCDEFGHJKLM'))->reason);
        self::assertSame(FailureReason::NOT_FOUND, $this->manager()->generateRecoveryCodes(Callers::current())->reason);
        self::assertNull($this->manager()->recoveryCodeStatus(Callers::current()));
        self::assertSame([], $this->manager()->proofs(Callers::current()));
        self::assertSame(FailureReason::NOT_FOUND, $this->manager()->removeFactor(Callers::current(), $this->guardedFactor->id)->reason);
        self::assertTrue(Factor::query()->whereKey($this->guardedFactor->id)->exists());
        self::assertSame([], $this->mailbox->sent());
        self::assertSame(0, RecoveryCode::query()->count());
    }

    /**
     * @return void
     *
     * @throws \Throwable
     */
    public function testWithoutAPendingSessionTheGuardsUserIsServed(): void
    {
        self::assertNotNull($this->manager()->recoveryCodeStatus(Callers::current()));
        self::assertCount(1, $this->manager()->proofs(Callers::current()));
        self::assertSame([$this->guardedFactor->id], array_map(static fn (FactorSummary $summary): string => $summary->id, $this->manager()->factors(Callers::current())));
    }

    /**
     * @return void
     *
     * @throws \Throwable
     */
    public function testListingServesThePendingPerson(): void
    {
        $this->pendingSession([PendingAction::LIST_FACTORS]);

        self::assertSame([$this->factor->id], array_map(static fn (FactorSummary $summary): string => $summary->id, $this->manager()->factors(Callers::current())));
        self::assertSame($this->factor->id, $this->manager()->factor(Callers::current(), $this->factor->id)?->id);
        self::assertNull($this->manager()->factor(Callers::current(), $this->guardedFactor->id));
        self::assertNotNull($this->manager()->recoveryCodeStatus(Callers::current()));
    }

    /**
     * @return void
     *
     * @throws \Throwable
     */
    public function testSendingAndVerifyingServeThePendingPerson(): void
    {
        $this->pendingSession([PendingAction::SEND_CODE, PendingAction::VERIFY]);

        $this->container()->make(ProofStore::class)->begin($this->pending, 'web', 'pending-1');

        $sent = $this->manager()->sendCode(Callers::current(), $this->factor->id);
        $code = $this->mailbox->lastCodeTo('pending@example.test');

        self::assertTrue($sent->wasSent());
        self::assertNotNull($sent->challengeId);
        self::assertNotNull($code);
        self::assertNull($this->mailbox->lastCodeTo('guarded@example.test'));
        self::assertTrue($this->manager()->verify(Callers::current(), Submission::challenge($this->factor->id, $sent->challengeId, $code))->isVerified());
    }

    /**
     * A session allowed only to send cannot verify the code it was sent.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testEachActionIsCheckedOnItsOwn(): void
    {
        $this->pendingSession([PendingAction::SEND_CODE]);

        $sent = $this->manager()->sendCode(Callers::current(), $this->factor->id);

        self::assertTrue($sent->wasSent());
        $code = (string) $this->mailbox->lastCodeTo('pending@example.test');

        $submission = Submission::challenge($this->factor->id, (string) $sent->challengeId, $code);

        self::assertSame(FailureReason::NOT_FOUND, $this->manager()->verify(Callers::current(), $submission)->reason);
    }

    /**
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnInvalidPendingCredentialPropagates(): void
    {
        $this->container()->instance(PendingSessionResolver::class, new FixedPendingSessionResolver(invalid: true));

        $this->expectException(InvalidPendingCredentialException::class);

        $this->manager()->factors(Callers::current());
    }

    /**
     * The refused code is not spent and verifies once the credential stands
     * again.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACallerRevokedOnceReadIsRefusedUnderTheLock(): void
    {
        $this->pendingSession([PendingAction::SEND_CODE, PendingAction::VERIFY]);
        $this->container()->make(ProofStore::class)->begin($this->pending, 'web', 'pending-1');

        $sent       = $this->manager()->sendCode(Callers::current(), $this->factor->id);
        $submission = Submission::challenge($this->factor->id, (string) $sent->challengeId, (string) $this->mailbox->lastCodeTo('pending@example.test'));
        $caller     = Callers::current();

        $this->container()->instance(PendingSessionResolver::class, new FixedPendingSessionResolver);

        self::assertSame(FailureReason::NOT_FOUND, $this->manager()->verify($caller, $submission)->reason);

        $this->pendingSession([PendingAction::SEND_CODE, PendingAction::VERIFY]);

        self::assertTrue($this->manager()->verify(Callers::current(), $submission)->isVerified());
    }

    /**
     * @return void
     *
     * @throws \Throwable
     */
    public function testThePresentedCredentialIsReadAgainUnderTheLock(): void
    {
        $first    = SignInProofs::of($this->pending)->inSession('pending-1')->password();
        $expiry   = CarbonImmutable::now()->addMinutes(10);
        $pending  = new PendingContext($this->pending, 'web', 'pending-1', $first, Requirement::none(), [PendingAction::SEND_CODE], $expiry, credential: 'presented-credential');
        $resolver = new RecordingPendingSessionResolver($pending);

        $this->container()->instance(PendingSessionResolver::class, $resolver);

        self::assertTrue($this->manager()->sendCode(Callers::current(), $this->factor->id)->wasSent());
        self::assertSame(['presented-credential'], $resolver->revalidated);
    }

    /**
     * @param  list<\SineMacula\Laravel\Mfa\Enums\PendingAction>  $actions
     * @return void
     */
    private function pendingSession(array $actions): void
    {
        $first = SignInProofs::of($this->pending)->inSession('pending-1')->password();

        $this->container()->instance(PendingSessionResolver::class, new FixedPendingSessionResolver(
            new PendingContext($this->pending, 'web', 'pending-1', $first, Requirement::none()->withAdditionalVerification(), $actions, CarbonImmutable::now()->addMinutes(10)),
        ));
    }

    /**
     * @param  \Tests\Fixtures\Identities\TestUser  $user
     * @param  string  $address
     * @return \SineMacula\Laravel\Mfa\Models\Factor
     */
    private function emailFactor(TestUser $user, string $address): Factor
    {
        /** @var \SineMacula\Laravel\Mfa\Models\Factor */
        return Factor::query()->create([
            'authenticatable_type' => $user::class,
            'authenticatable_id'   => (string) $user->id,
            'type'                 => 'email',
            'destination'          => $address,
            'status'               => 'confirmed',
            'confirmed_at'         => CarbonImmutable::now(),
        ]);
    }

    /**
     * @return \SineMacula\Laravel\Mfa\MfaManager
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function manager(): MfaManager
    {
        /** @var \SineMacula\Laravel\Mfa\MfaManager */
        return $this->container()->make('mfa');
    }
}
